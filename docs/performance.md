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

## 3. 적용된 최적화

### 3.1 Packet body — `Vec<u8>` → `Bytes` (zero-copy)

**Before:**
```rust
packet.body = body.to_vec();   // Bytes를 Vec으로 통째 alloc + copy
```

**After:**
```rust
packet.body = body.clone();    // Bytes::clone은 Arc 카운터 +1 (alloc 없음)
```

`bytes::Bytes`는 `Deref<Target=[u8]>`을 구현하므로 detector 코드(`fn extract_username(body: &[u8])`)는 변경 없이 zero-copy 호환된다. POST body가 큰 요청에서 효과가 크다.

### 3.2 PathScannerDetector — hot loop의 `format!` 제거

**Before:** 매 요청마다 28개 패턴 각각에 대해
```rust
path.starts_with(&format!("{}/", p))  // 패턴마다 String alloc
```
요청당 최대 28번의 `format!` String 할당.

**After:**
```rust
let pl = p.len();
path.len() > pl
    && path.as_bytes()[pl] == b'/'
    && path.as_bytes()[..pl] == *p.as_bytes()
```
모든 비교가 stack 위에서 끝남. URI 정규화는 `to_ascii_lowercase`로 ASCII만 처리(`to_lowercase()`는 유니코드 변환을 위해 추가 비용).

### 3.3 Ja3FingerprintDetector — `is_browser_ua` 한 번만 평가

**Before:** detect()가 분기에 따라 `is_browser_ua(&ua)`를 최대 2번 호출 — 각 호출마다 `String::contains` 4번 substring 검색.

**After:** 함수 진입 시 한 번만 계산해 boolean 변수로 재사용. UA가 길수록 효과 큼.

### 3.4 CredentialStuffingDetector — `to_lowercase()` 제거

**Before:** `is_login_endpoint(uri)`가 매 요청마다 `uri.to_lowercase()`로 새 String 생성.

**After:** `uri.as_bytes()[..ep.len()].eq_ignore_ascii_case(ep.as_bytes())` — alloc 없는 ASCII 비교. URI는 RFC상 ASCII 영역만 사용하므로 안전.

### 3.5 Block 시 early-exit

`Pipeline.run`은 `Action::Block` 발생 시 즉시 반환한다. 후속 detector가 무거운 검증(예: regex set 매치, body 파싱) 수행하지 않게 막는다. 명백한 봇은 Honeypot/IpRateLimiter/PathScanner 단계에서 끊긴다.

### 3.6 비동기 Kafka 전송

```rust
tokio::spawn(async move { kafka.send(&event).await });
```
탐지 결과 응답을 클라이언트에 보내는 경로와 Kafka 전송이 분리되어, Kafka가 느리거나 일시적으로 끊겨도 WAF 응답 latency에 영향을 주지 않는다.

### 3.7 정적 데이터의 한 번 로딩

- `UserAgentDetector`의 `RegexSet`은 시작 시 컴파일, 이후 모든 요청에서 재사용
- `Ja3FingerprintDetector`는 시작 시 파일에서 `HashSet<String>`으로 로드
- `PathScannerDetector::SCANNER_PATHS`는 컴파일 타임 `&[&str]`

## 4. 의도적으로 두는 비용

| 항목 | 이유 |
|------|------|
| `DetectionResult::reason: String` | reason에 IP/URI/스코어 같은 동적 값을 넣어야 함. Pass는 `String::from("pass")`로 기본 reason을 만들지만 hot path 영향 작음(짧은 문자열) |
| `Packet.headers: HashMap<String, String>` | axum HeaderMap을 그대로 들고 다니면 `&Packet`의 lifetime이 axum 요청 처리 컨텍스트에 묶임. detector 인터페이스 단순화를 위한 trade-off |
| `format!` 사용 (Block/Challenge 시점만) | 차단 사유 문자열은 사람이 읽어야 함. Pass에서는 호출되지 않으므로 정상 요청에는 영향 없음 |

## 5. 향후 고려 항목

검증/측정이 필요한 후보들. 적용 전에 벤치마크가 선행되어야 한다.

### 5.1 `HashMap<String, String>` → `ahash::HashMap` 또는 `FxHashMap`

기본 `HashMap`은 SipHash 해시를 쓴다(DoS 방어용). 헤더 키는 신뢰할 수 있는 nginx에서 오므로 더 빠른 해시(`ahash`, `rustc-hash`)로 교체 가능. 단, 외부 입력을 직접 키로 쓰는 곳(`username_ips`)은 그대로 둬야 안전.

### 5.2 `DetectionResult::reason: Cow<'static, str>`

Pass는 항상 같은 메시지("pass")이므로 `Cow::Borrowed("pass")`로 zero-alloc. 동적 reason만 `Cow::Owned(format!(...))`. 다만 `Pipeline.run`이 매 요청 9번 `DetectionResult::pass()`를 만들 수 있으니 미세 개선.

### 5.3 헤더 lookup 인덱싱

`HeaderFingerprintDetector`가 `accept`, `accept-language`, `accept-encoding`, `connection` 4개 키를 매번 hash lookup. 이걸 Packet build 시점에 미리 `Option<&str>` 4개 필드로 추출해두면 detector에서 hash 비용 없음.

### 5.4 JS Challenge / CAPTCHA 서명 — XOR → HMAC-SHA256

현재 XOR 기반 서명은 보안상 약하고(코드 주석에 명시됨), `format!("{b:02x}")` hex 변환에서 alloc이 다수 발생한다. `ring` 또는 `hmac` + `sha2`로 교체 시 보안과 성능 모두 개선 가능. (Challenge 요청에서만 호출되므로 hot path는 아님.)

### 5.5 Pipeline 병렬화는 부적합

각 detector가 가벼운 in-memory 연산이라 tokio task로 split하면 spawn 오버헤드가 더 크다. Block early-exit도 깨짐. 현재 순차 실행이 최적.

## 6. 관측 항목

성능 회귀를 잡으려면 측정이 필요하다. 현재는 별도 메트릭 없음 — 다음 단계 후보:

- Per-detector 실행 시간 (tracing span 또는 prometheus histogram)
- Pipeline.run 전체 시간
- Kafka send 큐 대기 시간

추가 시 `tracing`은 이미 사용 중이므로 `tracing-opentelemetry` + Prometheus exporter가 자연스럽다.
