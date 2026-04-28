# 성능 원칙 및 최적화

이 문서는 mini-protection 엔진의 hot path와 적용된 최적화 기법, 그리고 향후
추가로 고려할 만한 항목을 정리한다. 정상 요청 1건 처리 목표는 **1ms 미만**.

## 1. 코어 원칙 (CLAUDE.md 동기화)

| 원칙 | 적용 위치 |
|------|----------|
| 함수 인자는 소유권 이전 대신 `&` 참조 | 모든 `Detector::detect(&self, packet: &Packet)` |
| `String` 반환보다 `&'static str` / `Cow<'_, str>` 우선 | `Detector::name() -> &str` |
| 불필요한 `clone()` 금지 | `Pipeline`은 `Arc<dyn Detector>`로 보관, 매 요청 clone 없음 |
| heap 할당 최소화 | `Bytes`로 body 공유, hot path에서 `format!` 회피 |
| `DashMap` entry API로 lock 전환 최소화 | `IpRateLimiter`, `CredentialStuffingDetector` |
| `Arc<T>`로 공유, 복사 없이 참조 카운팅 | `HoneypotStore`, `KafkaProducer`, `Pipeline` |
| `detect()`는 `&Packet` 참조만 받음 | `pipeline/detector.rs` |
| zero-copy: Packet 데이터는 복사하지 않음 | `Packet.body: Bytes` (Arc 기반 공유 버퍼) |

## 2. Hot Path 분석

요청 한 건이 거치는 경로:

```
TCP accept (axum)
  → body.collect()                       ← Bytes로 누적, 추가 alloc 없음
  → build_packet(&parts, src_ip, &body)
       headers HashMap<String,String> 채우기  ← O(헤더 수) String alloc
       packet.body = body.clone()             ← Bytes Arc 카운터만 증가
  → Pipeline.run(&packet)
       각 Detector.detect(&packet)            ← 9개 detector 순차 실행
       Block 발생 시 즉시 반환
  → Action에 따라 분기:
       Pass     → upstream proxy
       Block    → block_response (HTML 생성)
       Challenge→ js_challenge_response
       Captcha  → captcha_response
  → Block/Challenge/Captcha 시 send_kafka_event
       tokio::spawn으로 비동기 전송, 메인 스레드 블로킹 없음
```

**가장 잦은 비용 (정상 Pass 요청 기준):**

1. axum → Packet 변환 시 헤더 String 복사 (수십 개 헤더)
2. `Pipeline.run`에서 9개 Detector 순차 호출
3. `proxy_upstream`의 hyper client 호출

## 3. 이번 라운드에서 적용한 최적화 (2026-04-28)

매 요청 hot path에서 발생하던 alloc 4건을 제거했다. 모두 commit `2fa814a`에 묶여 있다. 각 항목은 미래에 코드를 다시 보거나 재현/롤백/벤치마크할 때 필요한 정보를 담는 단위로 정리한다.

---

### 3.1 Packet.body 타입 변경 — `Vec<u8>` → `bytes::Bytes`

**위치**
- `rust-engine/src/packet/mod.rs:31` (필드 정의)
- `rust-engine/src/main.rs:413` (build_packet에서 할당)
- 테스트: `tests/unit/detectors/captcha.rs:29`, `tests/unit/detectors/credential_stuffing.rs:12`

**호출 빈도**
- 모든 인바운드 요청 1회 (Pass/Block 무관). 즉 가장 hot한 구간.

**변경 전**
```rust
// packet/mod.rs
pub body: Vec<u8>,

// main.rs build_packet
packet.body = body.to_vec();
```
- `body`는 hyper가 내려준 `bytes::Bytes` (Arc 기반 공유 버퍼).
- `to_vec()`은 내부 슬라이스를 새 heap 영역에 통째 memcpy → 매 요청 1회 `Vec<u8>::with_capacity + memcpy(body.len())`.
- POST 요청 body가 1MB라면 매 요청 1MB alloc + copy.

**변경 후**
```rust
// packet/mod.rs
use bytes::Bytes;
pub body: Bytes,

// main.rs build_packet
packet.body = body.clone();   // Arc 카운터 +1, 데이터 복사 없음
```

**왜 빨라지나**
- `Bytes::clone()`은 내부 `Arc<inner>`의 reference count만 증가시킨다(보통 atomic fetch_add 1 회). 데이터 메모리는 그대로 공유.
- 동일 요청 처리 흐름에서 hyper는 이미 `Bytes`로 buffering하므로 우리는 같은 buffer를 빌려 쓰기만 하면 된다.

**왜 안전한가 (인터페이스 호환성)**
- `bytes::Bytes`는 `impl Deref<Target = [u8]>`을 가진다.
- detector들은 `&packet.body`로 받아 `fn extract_username(body: &[u8])` 같은 함수에 넘긴다. 이 시점에 deref coercion이 자동으로 일어나 `&Bytes` → `&[u8]`. **detector 코드 수정 불필요.**
- 단, 테스트 코드는 `p.body = format!(...).into_bytes()` (Vec) 형태였기 때문에 `.into()` (String → Bytes)로 두 줄만 변경.

**제약 / 주의점**
- `Bytes`는 `&mut [u8]`을 직접 내주지 않는다. body를 in-place 수정하는 detector를 추가하려면 `BytesMut`로 받아 `freeze()`해 보관하는 패턴이 필요. 현재 detector는 모두 read-only이므로 무관.

**검증**: `cargo test --bin mini-protection-engine` → 101건 통과 (무회귀).

---

### 3.2 PathScannerDetector — 매 요청 28번의 `format!` 제거

**위치**: `rust-engine/src/detectors/path_scanner.rs:53-66`

**호출 빈도**
- Honeypot, IpRateLimiter 다음의 3번째 detector. 차단된 IP가 아닌 한 모든 요청에서 호출. 즉 정상 트래픽 전체.

**변경 전**
```rust
fn is_scanner_path(uri: &str) -> bool {
    let path = uri.split('?').next().unwrap_or(uri).to_lowercase();
    SCANNER_PATHS.iter().any(|p| {
        path == *p || path.starts_with(&format!("{}/", p))
    })
}
```
요청 1건당 비용:
1. `uri.to_lowercase()` — 새 `String` alloc 1회 (유니코드 case 매핑 테이블 lookup 포함).
2. `SCANNER_PATHS`(28개) loop 안에서 매 패턴마다 `format!("{}/", p)` — **요청당 최대 28번 `String` alloc**.

**변경 후**
```rust
fn is_scanner_path(uri: &str) -> bool {
    let path = uri.split('?').next().unwrap_or(uri).to_ascii_lowercase();
    SCANNER_PATHS.iter().any(|p| {
        if path == *p {
            return true;
        }
        let pl = p.len();
        path.len() > pl
            && path.as_bytes()[pl] == b'/'
            && path.as_bytes()[..pl] == *p.as_bytes()
    })
}
```

**왜 빨라지나**
1. `to_lowercase()` → `to_ascii_lowercase()`: URI는 RFC 3986에서 ASCII만 허용. 유니코드 case folding 테이블을 거치지 않고 단순 비트 OR로 처리. (alloc 횟수는 동일하나 변환 자체가 빨라짐.)
2. `format!("{}/", p)` 28회 alloc → byte slice 비교. heap에 손대지 않고 stack/정적 데이터에서 끝.

**의미적으로 동일한가**
- `path == p` (정확 일치) ‖ `path == "{p}/..."` (서브경로) — 의도는 그대로.
- byte 비교: `path.as_bytes()[..pl] == *p.as_bytes()` — `&[u8]` 동치. 길이 검사를 먼저 해서 panic 방지(`path.len() > pl`).
- 슬라이싱 인덱스 안전: `path.len() > pl`이므로 `path.as_bytes()[pl]` 접근 OK.

**제약 / 주의점**
- `SCANNER_PATHS`의 모든 항목은 이미 소문자(`/.env`, `/wp-admin` 등)이므로 lowercase 비교가 의미 있음. 누군가 새 패턴을 대문자로 추가하면 매칭 실패 — 패턴 추가 시 소문자 유지 규칙을 기억해야 한다.

**검증**: PathScanner 단위 테스트(case insensitivity, sub-path 매칭, query string 무시 등)가 모두 통과. 운영 로그 상 `/.env`, `/wp-admin`, `/.git/config` 같은 실제 스캐너 트래픽이 그대로 Block됨을 EC2 로그에서 확인.

---

### 3.3 Ja3FingerprintDetector — `is_browser_ua` 중복 평가 제거

**위치**: `rust-engine/src/detectors/ja3_fingerprint.rs:66-95`

**호출 빈도**
- `X-JA3-Fingerprint` 헤더를 가진 모든 요청(현재 OpenResty가 거의 모든 HTTPS 요청에 부여). 즉 운영 트래픽 거의 전부.

**변경 전**
```rust
if self.whitelist.contains(ja3) && is_browser_ua(&packet.user_agent) {
    return DetectionResult::pass();
}

let reason = if self.whitelist.contains(ja3) {
    format!("JA3 in whitelist but non-browser UA: {ja3}")
} else if is_browser_ua(&packet.user_agent) {
    format!("Browser UA but JA3 ({ja3}) not in whitelist")
} else {
    format!("Unknown UA and JA3: {ja3}")
};
```
- `is_browser_ua`는 내부적으로 `String::contains`를 4번(`Mozilla/5.0`, `Chrome/`, `Firefox/`, `Safari/`) 호출하는 substring 검색.
- 분기에 따라 같은 함수가 **최대 2번 호출**, `whitelist.contains`도 최대 2번.

**변경 후**
```rust
let is_browser = is_browser_ua(&packet.user_agent);
let is_whitelisted = self.whitelist.contains(ja3);

if is_whitelisted && is_browser {
    return DetectionResult::pass();
}

let reason = if is_whitelisted {
    format!("JA3 in whitelist but non-browser UA: {ja3}")
} else if is_browser {
    format!("Browser UA but JA3 ({ja3}) not in whitelist")
} else {
    format!("Unknown UA and JA3: {ja3}")
};
```

**왜 빨라지나**
- `is_browser_ua`는 substring 검색이라 UA 길이 N에 대해 O(N×4). 일반 Chrome UA는 130자 내외 → 약 500여 byte 비교/요청 절감.
- `whitelist.contains`는 SipHash 기반 HashSet lookup — 한 번에 절감.

**의미 변화 없음**
- 짧은-circuit 평가가 사라지지만(이전엔 `whitelist.contains`가 false면 `is_browser_ua` 평가 안 함), 이후 분기에서 어차피 둘 다 필요하므로 결과 동일.

**검증**: `cargo test` 통과. JA3 단위 테스트(블랙리스트, 화이트리스트+브라우저, 비브라우저 + 화이트 등 5케이스) 그대로 동작.

---

### 3.4 CredentialStuffingDetector.is_login_endpoint — `to_lowercase()` 제거

**위치**: `rust-engine/src/detectors/credential_stuffing.rs:37-42`

**호출 빈도**
- Detector 7번째이지만 `is_login_endpoint`는 detect() 진입 직후 호출되므로 모든 요청 1회. POST가 아닌 요청도 여기서 짧은-circuit으로 빠진다(`if !is_login_endpoint { return Pass }` → 정상 요청은 여기서 종료).

**변경 전**
```rust
fn is_login_endpoint(uri: &str) -> bool {
    let uri_lower = uri.to_lowercase();
    LOGIN_URIS.iter().any(|&ep| uri_lower.starts_with(ep))
}
```
- 매 요청 `uri.to_lowercase()` → 새 `String` alloc.
- 정상 요청 99%는 `/login`, `/signin` 같은 패턴이 아닌데도 alloc 비용을 지불.

**변경 후**
```rust
fn is_login_endpoint(uri: &str) -> bool {
    LOGIN_URIS.iter().any(|&ep| {
        uri.len() >= ep.len()
            && uri.as_bytes()[..ep.len()].eq_ignore_ascii_case(ep.as_bytes())
    })
}
```

**왜 빨라지나**
- `eq_ignore_ascii_case`는 byte slice끼리 ASCII case-insensitive 비교 (각 바이트를 `b' '`로 OR해서 비교) — alloc 없이 stack에서 처리.
- alloc 1회 → 0회 / 요청.

**왜 안전한가**
- HTTP path는 RFC 3986상 ASCII만 허용. 한글 등은 percent-encoding된다(`%ED%95%9C`). 따라서 ASCII case insensitivity로 충분.
- 길이 가드(`uri.len() >= ep.len()`)로 슬라이싱 panic 방지.

**제약**
- `LOGIN_URIS`의 모든 항목은 소문자라야 한다(현재 그렇다). 새 항목 추가 시 소문자 유지.

**검증**: CredentialStuffing 단위 테스트(IP threshold, username 분산 공격, non-login pass 등) 통과.

---

## 4. 이전부터 있던 구조적 최적화

이번 라운드에서 변경하지 않았지만 성능에 기여하는 항목들. 같이 알아둘 가치 있음.

### 4.1 Block early-exit (`pipeline/mod.rs:46`)

`Pipeline.run`은 `Action::Block` 발생 시 즉시 `return`한다. 명백한 봇은 Honeypot / IpRateLimiter / PathScanner 단계에서 차단되어 뒤따르는 무거운 검증(JA3 HashSet lookup, RegexSet 매치, body 파싱)을 회피.

### 4.2 비동기 Kafka 전송 (`main.rs:149`)

```rust
tokio::spawn(async move { kafka.send(&event).await });
```
응답 경로와 Kafka 전송이 분리되어 Kafka 지연/장애가 WAF latency에 직접 전이되지 않음. 단점: 백프레셔 없음 — 폭주 시 spawn된 task가 누적될 수 있다(현재까진 문제 없음, 부하 시점에 재검토).

### 4.3 정적 데이터 1회 로딩

- `UserAgentDetector::RegexSet`: 시작 시 컴파일, 매 요청 재사용
- `Ja3FingerprintDetector`: `HashSet<String>`으로 시작 시 파일 로드 (45 + 29 항목)
- `PathScannerDetector::SCANNER_PATHS`: 컴파일 타임 `&[&str]`

### 4.4 Detector를 `Arc<dyn Detector>`로 보관 (`pipeline/mod.rs:17`)

매 요청에서 `Pipeline`을 clone하지 않음. `AppState`도 Detector 인스턴스를 통째 Arc로 공유. CPU 코어 수만큼의 worker thread가 같은 인스턴스를 동시에 호출.

### 4.5 DashMap entry API (`ip_rate_limiter.rs:85-88`, `credential_stuffing.rs:124, 180`)

```rust
let mut entry = self.entries.entry(packet.src_ip)
    .or_insert_with(|| IpEntry::new(packet.src_ip, now));
```
shard 락 1회 잡고 카운터 증가까지 끝냄. 별도 `get` → `insert` 두 번 락 잡는 패턴 회피.

## 5. 의도적으로 두는 비용

| 항목 | 이유 |
|------|------|
| `DetectionResult::reason: String` | reason에 IP/URI/스코어 같은 동적 값을 넣어야 함. Pass는 `String::from("pass")`로 기본 reason을 만들지만 hot path 영향 작음(짧은 문자열) |
| `Packet.headers: HashMap<String, String>` | axum HeaderMap을 그대로 들고 다니면 `&Packet`의 lifetime이 axum 요청 처리 컨텍스트에 묶임. detector 인터페이스 단순화를 위한 trade-off |
| `format!` 사용 (Block/Challenge 시점만) | 차단 사유 문자열은 사람이 읽어야 함. Pass에서는 호출되지 않으므로 정상 요청에는 영향 없음 |

## 6. 향후 고려 항목

검증/측정이 필요한 후보들. 적용 전에 벤치마크가 선행되어야 한다.

### 6.1 `HashMap<String, String>` → `ahash::HashMap` 또는 `FxHashMap`

기본 `HashMap`은 SipHash 해시를 쓴다(DoS 방어용). 헤더 키는 신뢰할 수 있는 nginx에서 오므로 더 빠른 해시(`ahash`, `rustc-hash`)로 교체 가능. 단, 외부 입력을 직접 키로 쓰는 곳(`username_ips`)은 그대로 둬야 안전.

### 6.2 `DetectionResult::reason: Cow<'static, str>`

Pass는 항상 같은 메시지("pass")이므로 `Cow::Borrowed("pass")`로 zero-alloc. 동적 reason만 `Cow::Owned(format!(...))`. 다만 `Pipeline.run`이 매 요청 9번 `DetectionResult::pass()`를 만들 수 있으니 미세 개선.

### 6.3 헤더 lookup 인덱싱

`HeaderFingerprintDetector`가 `accept`, `accept-language`, `accept-encoding`, `connection` 4개 키를 매번 hash lookup. 이걸 Packet build 시점에 미리 `Option<&str>` 4개 필드로 추출해두면 detector에서 hash 비용 없음.

### 6.4 JS Challenge / CAPTCHA 서명 — XOR → HMAC-SHA256

현재 XOR 기반 서명은 보안상 약하고(코드 주석에 명시됨), `format!("{b:02x}")` hex 변환에서 alloc이 다수 발생한다. `ring` 또는 `hmac` + `sha2`로 교체 시 보안과 성능 모두 개선 가능. (Challenge 요청에서만 호출되므로 hot path는 아님.)

### 6.5 Pipeline 병렬화는 부적합

각 detector가 가벼운 in-memory 연산이라 tokio task로 split하면 spawn 오버헤드가 더 크다. Block early-exit도 깨짐. 현재 순차 실행이 최적.

## 7. 관측 항목

성능 회귀를 잡으려면 측정이 필요하다. 현재는 별도 메트릭 없음 — 다음 단계 후보:

- Per-detector 실행 시간 (tracing span 또는 prometheus histogram)
- Pipeline.run 전체 시간
- Kafka send 큐 대기 시간

추가 시 `tracing`은 이미 사용 중이므로 `tracing-opentelemetry` + Prometheus exporter가 자연스럽다.
