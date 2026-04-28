# WAF Bot Detection Engine — 기술 설명서

이 문서는 시스템의 동작 방식, 기술적 구현, 설계 결정을 처음부터 끝까지 설명한다.

---

## 목차

1. [전체 흐름 한눈에 보기](#1-전체-흐름-한눈에-보기)
2. [컴포넌트별 역할](#2-컴포넌트별-역할)
3. [핵심 자료구조 — Packet](#3-핵심-자료구조--packet)
4. [탐지 파이프라인 설계](#4-탐지-파이프라인-설계)
5. [Detector 1 — Honeypot](#5-detector-1--honeypot)
6. [Detector 2 — IP Rate Limiter](#6-detector-2--ip-rate-limiter)
7. [Detector 3 — Path Scanner](#7-detector-3--path-scanner)
8. [Detector 4 — JA3 Fingerprint](#8-detector-4--ja3-fingerprint)
9. [Detector 5 — User-Agent Detection](#9-detector-5--user-agent-detection)
10. [Detector 6 — Header Fingerprint](#10-detector-6--header-fingerprint)
11. [Detector 7 — Credential Stuffing](#11-detector-7--credential-stuffing)
12. [Detector 8 — JS Challenge](#12-detector-8--js-challenge)
13. [Detector 9 — CAPTCHA](#13-detector-9--captcha)
14. [응답 생성 — challenge/mod.rs](#14-응답-생성--challengemodrs)
15. [메인 서버 — main.rs](#15-메인-서버--mainrs)
16. [Kafka 이벤트 스트리밍](#16-kafka-이벤트-스트리밍)
17. [동시성 모델](#17-동시성-모델)
18. [보안 설계 포인트](#18-보안-설계-포인트)
19. [테스트 전략](#19-테스트-전략)
20. [설계 결정과 트레이드오프](#20-설계-결정과-트레이드오프)

---

## 1. 전체 흐름 한눈에 보기

```
[클라이언트]
     │  HTTP 요청
     ▼
[nginx:80]
  - 클라이언트 연결 수락
  - X-Real-IP 헤더에 실제 IP 삽입
  - rust-engine으로 모든 요청 프록시
     │
     ▼
[rust-engine:8080]  ←── 이곳이 WAF의 핵심
  ① HTTP 요청 수신 (axum)
  ② Request → Packet 변환
  ③ JS 챌린지 쿠키 검증 → packet.js_challenge_passed 설정
  ④ Pipeline.run(&packet) 실행
       ├─ HoneypotDetector.detect()
       ├─ IpRateLimiter.detect()
       ├─ PathScannerDetector.detect()
       ├─ Ja3FingerprintDetector.detect()
       ├─ UserAgentDetector.detect()
       ├─ HeaderFingerprintDetector.detect()
       ├─ CredentialStuffingDetector.detect()
       ├─ JsChallengeDetector.detect()
       └─ CaptchaDetector.detect()
  ⑤ 최종 Action 결정
       ├─ Pass    → upstream(backend)으로 프록시
       ├─ Block   → 403 JSON 응답
       ├─ Challenge → JS Challenge HTML 응답
       └─ Captcha  → reCAPTCHA HTML 응답
  ⑥ Block/Challenge/Captcha면 Kafka로 이벤트 전송 (비동기)
     │
     ├─[Pass]──→ [backend:8080] go-httpbin (테스트용 백엔드)
     │
     └─[Kafka]  mini-protection-events 토픽 → event-viewer / SIEM / 분석 시스템
```

요청 한 건이 WAF를 통과하는 데 걸리는 시간은 정상 요청 기준 1ms 미만이다.

---

## 2. 컴포넌트별 역할

### nginx

```nginx
location / {
    proxy_pass http://rust-engine:8080;
    proxy_set_header X-Real-IP $remote_addr;   # 실제 클라이언트 IP 전달
}
```

nginx는 WAF 로직을 하나도 갖지 않는다. 역할은 두 가지다.

1. **TCP 연결 관리**: 클라이언트와의 연결을 빠르게 수락하고 버퍼링한다.
2. **X-Real-IP 삽입**: `$remote_addr`(클라이언트 IP)를 헤더로 넣어 rust-engine에 전달한다.

nginx 없이 rust-engine을 80포트에 직접 바인딩할 수도 있지만, 실제 운영에서는 TLS 종단, 로드밸런싱, 정적 파일 서빙 같은 작업을 nginx가 담당하는 게 일반적이다.

### rust-engine

axum 기반 비동기 HTTP 서버. WAF의 모든 탐지 로직이 여기에 있다. 단일 프로세스에서 tokio 런타임으로 멀티스레드 비동기 처리를 한다.

### backend

실제 서비스 서버. 이 프로젝트에서는 테스트용 `mccutchen/go-httpbin` 컨테이너로 대체했다(8080 포트). httpbin은 `/get`, `/post`, `/headers`, `/cookies` 등 다양한 엔드포인트로 요청 echo를 제공해 WAF 동작 검증이 쉽다. Pass된 요청만 도달한다.

### Kafka

탐지 이벤트를 실시간으로 스트리밍한다. WAF 자체는 Kafka 없이도 동작하지만, Kafka가 있으면 탐지 결과를 외부 SIEM, 분석 대시보드, 알림 시스템으로 내보낼 수 있다.

---

## 3. 핵심 자료구조 — Packet

```rust
pub struct Packet {
    pub src_ip: IpAddr,        // 클라이언트 IP (X-Real-IP 또는 TCP 연결 IP)
    pub dst_ip: IpAddr,        // WAF IP
    pub timestamp: u64,        // 요청 수신 시각 (Unix ms)
    pub method: String,        // GET, POST, ...
    pub uri: String,           // /login?foo=bar
    pub http_version: String,  // HTTP/1.1
    pub headers: HashMap<String, String>,  // 소문자 정규화
    pub user_agent: String,
    pub host: String,
    pub referer: String,
    pub body: Vec<u8>,         // 요청 바디 (raw bytes)
    pub cookie: HashMap<String, String>,  // 파싱된 쿠키
    pub js_challenge_passed: bool,        // JS 챌린지 통과 여부
    pub captcha_passed: bool,             // CAPTCHA 통과 여부
    pub violation_count: u32,             // 누적 위반 횟수
    pub ja3_fingerprint: Option<String>,  // TLS JA3 해시 (X-JA3-Fingerprint 헤더)
}
```

**왜 이 구조가 중요한가?**

모든 Detector는 `&Packet`만 받는다. 소유권을 빼앗지 않고 읽기만 한다. 파이프라인에서 9개 Detector가 동일한 Packet을 순서대로 읽는다.

```rust
// pipeline/mod.rs
pub fn run(&self, packet: &Packet) -> DetectionResult {
    for detector in &self.detectors {
        let result = detector.detect(packet);  // &Packet 전달, 복사 없음
        ...
    }
}
```

헤더 이름은 모두 소문자로 정규화된다. `Content-Type`이든 `content-type`이든 `packet.headers.get("content-type")`으로 동일하게 접근한다. 대소문자 비교 실수를 원천 차단하는 설계다.

---

## 4. 탐지 파이프라인 설계

### Detector trait

```rust
pub trait Detector: Send + Sync {
    fn detect(&self, packet: &Packet) -> DetectionResult;
    fn name(&self) -> &str;
}
```

`Send + Sync`가 붙어있어 Arc에 넣어 멀티스레드 환경에서 공유할 수 있다. 모든 탐지 모듈은 이 trait를 구현하기만 하면 파이프라인에 꽂힌다.

### Action 우선순위

```rust
#[derive(PartialOrd, Ord)]
pub enum Action {
    Pass,
    Challenge,
    Captcha,
    Block,     // 가장 높은 우선순위
}
```

Rust의 `#[derive(Ord)]`를 활용해서 열거형 선언 순서가 곧 우선순위다. `Block > Captcha > Challenge > Pass`.

### 파이프라인 실행 로직

```rust
pub fn run(&self, packet: &Packet) -> DetectionResult {
    let mut worst = DetectionResult::pass();  // 초기값: Pass

    for detector in &self.detectors {
        let result = detector.detect(packet);

        if result.action == Action::Block {
            return result;  // Block은 즉시 반환 (early exit)
        }

        if result.action > worst.action {
            worst = result;  // 더 심각한 결과를 유지
        }
    }

    worst
}
```

Block이 아닌 경우 파이프라인은 계속 실행되고, 가장 높은 우선순위 결과를 최종으로 선택한다. 예를 들어 HeaderFingerprint가 Challenge를, Captcha가 Pass를 반환하면 최종 결과는 Challenge다.

Block은 early exit이다. IpRateLimiter가 Block을 반환하면 나머지 7개 Detector는 실행하지 않는다.

### Detector 등록 (main.rs)

```rust
let pipeline = Arc::new(Pipeline::new(vec![
    Box::new(HoneypotDetector::new(Arc::clone(&honeypot_caught))),
    Box::new(detectors::ip_rate_limiter::IpRateLimiter::new()),
    Box::new(detectors::path_scanner::PathScannerDetector::new()),
    Box::new(detectors::ja3_fingerprint::Ja3FingerprintDetector::new()),
    Box::new(detectors::user_agent::UserAgentDetector::new()),
    Box::new(detectors::header_fingerprint::HeaderFingerprintDetector::new()),
    Box::new(detectors::credential_stuffing::CredentialStuffingDetector::new()),
    Box::new(JsChallengeDetector::with_secret(js_secret.clone())),
    Box::new(CaptchaDetector::new()),
]));
```

새 탐지 모듈을 추가하려면 `detectors/` 에 파일 만들고 `Detector` trait 구현하고 이 벡터에 추가하면 끝이다.

---

## 5. Detector 1 — Honeypot

### 역할

HTML 응답에 눈에 보이지 않는 트랩 링크를 주입한다. 봇이 링크를 파싱해서 따라오면 IP를 기록하고, 이후 해당 IP의 모든 요청을 영구 차단한다.

### 동작 흐름

```
1. upstream HTML 응답에 숨겨진 <a> 링크 주입
   <a href="/__mini-protection/trap" style="display:none;..."> </a>

2. 봇이 링크를 파싱하여 /__mini-protection/trap 에 GET 요청

3. honeypot_trap_handler:
   - IP를 HoneypotStore(DashMap<IpAddr, ()>)에 기록
   - 404 반환 (스마트 봇이 탐지 사실을 알아채기 어렵게)
   - Kafka 이벤트 전송

4. 이후 모든 요청: HoneypotDetector가 HoneypotStore 확인 → Block
```

### 왜 트랩 엔드포인트가 404를 반환하는가

200을 반환하면 "트랩에 걸렸다는 신호"를 봇이 알아채고 해당 IP를 기피할 수 있다. 404는 봇 입장에서 "없는 경로를 잘못 방문했다"처럼 보인다.

### HoneypotStore 공유 구조

```rust
// main.rs에서 생성
let honeypot_caught: HoneypotStore = Arc::new(DashMap::new());

// Pipeline에 넣는 Detector와 trap_handler가 동일 Arc를 참조
Box::new(HoneypotDetector::new(Arc::clone(&honeypot_caught)))
state.honeypot_caught.insert(src_ip, ());  // trap_handler에서 직접 기록
```

trap_handler와 HoneypotDetector가 같은 DashMap을 Arc로 공유한다. trap_handler가 IP를 기록하면 그 다음 요청부터 HoneypotDetector가 Block을 반환한다.

---

## 6. Detector 2 — IP Rate Limiter

### 역할

IP당 분당 요청 수를 제한한다. 스크레이퍼, DDoS, 자동화 툴이 짧은 시간에 대량 요청을 날리는 걸 막는다.

### 상태 저장 구조

```rust
pub struct IpRateLimiter {
    entries: DashMap<IpAddr, IpEntry>,  // IP → 상태 레코드
}

pub struct IpEntry {
    count: u32,           // 현재 윈도우 내 요청 횟수
    window_start: u64,    // 현재 윈도우 시작 시각 (Unix seconds)
    violation_cnt: u32,   // 누적 위반 횟수
    blocked: bool,        // 현재 차단 상태
    blocked_until: u64,   // 차단 해제 시각 (0=없음, MAX=영구)
}
```

`DashMap`은 내부적으로 샤딩된 해시맵이다. 락 충돌 없이 여러 스레드가 동시에 다른 IP를 읽고 쓸 수 있다. 전통적인 `Mutex<HashMap>`보다 훨씬 효율적이다.

### Sliding Window 알고리즘

```
요청 시각: now

1. now - window_start >= 60초 이면
   → count = 0, window_start = now  (새 윈도우)

2. count += 1

3. count > 10 이면 → Block
```

Sliding Window는 이전 윈도우의 가중치를 고려하지 않는 단순 구현이다. 59초에 10번, 61초에 10번처럼 윈도우 경계를 타면 실제로는 2초 안에 20번이 허용된다. 정밀한 Sliding Window Log 알고리즘보다 메모리가 적게 든다는 트레이드오프를 감수한 선택이다.

### 누적 차단 정책

```rust
fn block_until(violation_cnt: u32, now: u64) -> u64 {
    match violation_cnt {
        1 => now + 60,    // 1분
        2 => now + 300,   // 5분
        3 => now + 1800,  // 30분
        _ => u64::MAX,    // 영구 차단
    }
}
```

위반을 반복할수록 차단 시간이 기하급수적으로 늘어난다. 4번 위반하면 영구 차단이다. `u64::MAX`는 "절대로 해제되지 않음"을 표현하는 sentinel 값이다.

---

## 7. Detector 3 — Path Scanner

### 역할

알려진 취약점 열거 경로에 대한 접근을 차단한다. `.env`, `.git`, `wp-admin`, `phpmyadmin` 같은 경로에 접근하는 것은 스캐너나 봇의 정찰 행위다.

### 매칭 방식

```rust
// 쿼리스트링 제거 후 소문자 정규화
let path = uri.split('?').next().unwrap_or(uri).to_lowercase();

// 하위 경로까지 포함하여 매칭
// /wp-admin/post.php → "wp-admin" prefix 매칭 → Block
SCAN_PATHS.iter().any(|p| path == *p || path.starts_with(&format!("{}/", p)))
```

`/.env?foo=bar` → `/.env` 정규화 후 매칭 → Block.
`/.ENV` → `.env` 소문자 변환 후 매칭 → Block.

### 탐지 경로 예시 (28개)

`.env`, `.git/`, `wp-admin`, `phpmyadmin`, `xmlrpc.php`, `shell.php`, `/etc/passwd`, `actuator/`, `telescope/`, `config.php`, `backup/`, `.DS_Store`, `admin/`, `phpinfo.php` 등.

### 경로 매칭 정밀도

루트 시크릿 경로만 차단한다. 예: `/.git`(루트 숨김 폴더)은 Block, `/alice/my-repo.git` 같이 path 중간에 `.git`이 포함된 경로는 통과. 매칭 규칙은 `path == p || (path.starts_with(p) && path[p.len()] == '/')` 이므로 prefix가 아닌 정확한 경로 단위로만 일치한다.

---

## 8. Detector 4 — JA3 Fingerprint

### 역할

TLS 핸드셰이크에서 클라이언트가 보내는 cipher suite, extension 조합을 MD5로 해시한 JA3 지문을 기반으로 봇을 탐지한다. User-Agent는 위조 가능하지만 JA3는 TLS 라이브러리 수준에서 결정되어 위조하기 어렵다.

### 인프라 요구사항

JA3는 TLS 레이어에서 계산되므로 **nginx-module-ja3 또는 OpenResty + HTTPS 설정**이 필요하다. 현재 시스템은 OpenResty(443 HTTPS) + Lua `ssl_client_hello_by_lua_block`에서 ClientHello를 파싱해 JA3 해시를 계산하고 `X-JA3-Fingerprint` 헤더로 rust-engine에 전달한다. 블랙리스트 45개 / 화이트리스트 29개 항목으로 활성화 운영 중이며, 자세한 매칭 규칙은 `detection-rules.md` 참조.

### 탐지 로직 (4단계)

```
1. X-JA3-Fingerprint 헤더 없음 → Pass (하위 호환)

2. JA3가 봇 블랙리스트에 있음 → Block
   "Blacklisted JA3 fingerprint: {hash} (python-requests 2.4.3)"

3. JA3가 브라우저 화이트리스트에 있음 → Pass

4. 브라우저 UA이지만 미등록 JA3 → Challenge
   (Chrome 110+/Firefox 114+는 extension 순서를 랜덤화 → Block 시 false positive 급증)

5. 알 수 없는 UA + 미등록 JA3 → Challenge
```

### 브라우저 JA3 랜덤화 문제

Chrome 110+와 Firefox 114+부터 TLS ClientHello의 extension 순서를 매 요청마다 랜덤화한다. 동일한 Chrome 브라우저가 요청마다 다른 JA3를 생성하므로 브라우저 화이트리스트는 불완전하다. 이 때문에 규칙 4를 Block 대신 Challenge로 처리한다.

### 핵심 가치 — UA 위장 봇 탐지

```
봇(python-requests)이 User-Agent를 Chrome으로 위장
→ UserAgentDetector: Pass (Chrome UA로 보임)
→ Ja3FingerprintDetector: Block (JA3 = "c398c55..." python-requests)
```

UA는 속여도 TLS 라이브러리는 속이기 어렵다.

---

## 9. Detector 5 — User-Agent Detection

### 역할

HTTP 요청의 `User-Agent` 헤더를 보고 알려진 봇/스캐너/자동화 도구를 탐지한다.

### 탐지 로직 (3단계)

```
1. UA가 비어있음 → Block (브라우저는 반드시 UA를 보냄)

2. 블랙리스트 regex 매칭 → Block
   예: python-requests, curl, wget, scrapy, bot, selenium, sqlmap ...

3. 화이트리스트 regex 매칭 → Pass
   예: Mozilla/5.0 ... Chrome/숫자, Firefox/숫자, Edg/숫자 ...

4. 둘 다 아님 → Challenge (알 수 없는 클라이언트)
```

### RegexSet 활용

```rust
// N개 패턴을 한 번의 스캔으로 검사
self.blacklist.is_match(ua)  // O(패턴 수) → O(1) 수준
```

`regex::RegexSet`은 여러 정규식을 하나의 DFA로 컴파일한다. 17개 블랙리스트 패턴을 UA 문자열에 순서대로 적용하는 게 아니라 한 번에 매칭한다. 패턴이 늘어나도 성능이 선형으로 증가하지 않는다.

### 패턴 주입 (with_config)

```rust
UserAgentDetector::with_config(UserAgentConfig {
    blacklist_patterns: Some(vec!["my-scanner".to_string()]),
    whitelist_patterns: None,  // None이면 기본값 사용
})
```

기본 패턴 외에 운영 환경에서 커스텀 패턴을 주입할 수 있다.

---

## 10. Detector 6 — Header Fingerprint

### 역할

브라우저는 특정 헤더를 반드시 보낸다. 이 헤더들이 없거나 이상하면 봇일 가능성이 높다. 점수를 매겨서 판정한다.

### 점수 체계

| 조건 | 점수 | 이유 |
|------|------|------|
| `Accept: */*` 만 | +30 | 브라우저는 `text/html,...` 등 구체적 타입을 보냄 |
| `Accept-Language` 없음 | +30 | 브라우저는 반드시 언어 헤더를 보냄 |
| `Accept-Encoding` 없음 | +20 | 브라우저는 gzip 등 압축을 지원함 |
| `Connection: close` | +20 | 브라우저는 keep-alive를 선호함 |

```
0~30점  → Pass      (정상 또는 의심스럽지만 통과)
31~60점 → Challenge (JS Challenge 발급)
61점~   → Block     (명백한 봇 패턴)
```

**실제 예시:**
- 정상 Chrome: Accept 구체적 + Language 있음 + Encoding 있음 = 0점 → Pass
- curl: Accept: */* (+30) + Language 없음 (+30) + Encoding 없음 (+20) = 80점 → Block
- 불완전한 스크립트: Accept: */* (+30) + Encoding 없음 (+20) = 50점 → Challenge

### 한계

이 방법은 정밀도가 낮다. 잘 만든 봇은 브라우저 헤더를 흉내낸다. 하지만 게으른 봇이나 기본 HTTP 라이브러리를 그대로 쓰는 공격자를 효과적으로 걸러낸다. 이후 JS Challenge와 CAPTCHA가 더 정밀하게 검증한다.

---

## 11. Detector 7 — Credential Stuffing

### 역할

로그인 엔드포인트에 대한 자격증명 대입 공격을 탐지한다. 두 가지 패턴을 감지한다.

1. **집중 공격**: 동일 IP에서 단시간에 다수 로그인 시도
2. **분산 공격**: 동일 username을 여러 IP에서 나눠서 시도

### 두 개의 카운터

```rust
pub struct CredentialStuffingDetector {
    ip_counters:  DashMap<IpAddr,  IpLoginEntry>,   // IP → 시도 횟수
    username_ips: DashMap<String,  UsernameEntry>,  // username → 시도한 IP 목록
}
```

**IP 카운터**: IP당 60초 안에 5번 초과 시 5분 차단.

**Username 카운터**: 동일 username으로 4개 이상의 서로 다른 IP에서 시도하면 분산 공격으로 판단.

```rust
// username별로 시도한 IP를 중복 없이 추적
if !entry.ips.contains(&ip) {
    entry.ips.push(ip);
}
if entry.ips.len() > USERNAME_IP_THRESHOLD {
    → Block  // "distributed attack on username 'victim' from 5 IPs"
}
```

### 엔드포인트 감지

```rust
const LOGIN_URIS: &[&str] = &[
    "/login", "/signin", "/auth",
    "/api/login", "/api/signin", "/api/auth",
    "/user/login", "/account/login",
];
```

POST 요청이고 URI가 이 목록으로 시작할 때만 검사한다. GET /home 같은 일반 요청은 즉시 Pass한다.

### username 추출

POST body를 `form-urlencoded` 형식으로 파싱한다.

```rust
fn extract_username(body: &[u8]) -> Option<String> {
    // username=, email=, id= 필드 중 하나를 찾음
    body_str.split('&').find_map(|pair| {
        if key == "username" || key == "email" || key == "id" { ... }
    })
}
```

---

## 12. Detector 8 — JS Challenge

### 역할

JavaScript를 실행할 수 없는 봇을 걸러낸다. 브라우저는 JS를 실행할 수 있지만, 대부분의 HTTP 봇(requests, curl 등)은 JS를 실행하지 못한다.

### 동작 흐름

```
1. 쿠키 없음 → Challenge 응답 (JS Challenge HTML 반환)
   브라우저가 HTML을 받아 JS를 실행하면:
     window.innerWidth, window.innerHeight를 hidden form에 넣고
     /__waf/js-challenge/verify 로 자동 POST

2. verify 핸들러:
   width > 0 && height > 0 확인 (봇은 0 또는 미제출)
   → 유효하면 서명된 쿠키 발급 후 원래 URL로 redirect

3. 다음 요청에 쿠키 포함 → Pass
```

### 쿠키 구조

```
waf_js_challenge={timestamp}:{ip}:{signature}

예: 1700000000:192.168.1.1:a3f5c2...
```

- `timestamp`: 발급 시각. TTL(1시간) 초과 시 만료 처리.
- `ip`: 쿠키를 발급받은 IP. 다른 IP에서 재사용 불가.
- `signature`: `timestamp:ip`를 secret으로 XOR 서명.

### 서명 검증

```rust
fn verify_cookie_value(value: &str, ip: &str, secret: &[u8]) -> Result<bool, &'static str> {
    // 1. 포맷 분리 (timestamp:ip:sig)
    // 2. IP 일치 확인 → 불일치면 Err("ip mismatch") → Block
    // 3. 서명 검증 → 불일치면 Err("signature invalid") → Block
    // 4. 만료 확인 → 만료면 Ok(false) → Challenge (재발급)
    // 5. 정상이면 Ok(true) → Pass
}
```

위변조된 쿠키(서명 불일치, IP 불일치)는 Challenge가 아닌 **Block**으로 처리한다. 의도적으로 쿠키를 조작한 것이기 때문이다.

### proxy_handler에서의 전처리

파이프라인을 실행하기 전에 JS 쿠키를 먼저 검증하고 `packet.js_challenge_passed`를 설정한다.

```rust
// main.rs - proxy_handler
let mut packet = build_packet(&parts, src_ip, &body_bytes);

if let Some(cookie_val) = packet.cookie.get("waf_js_challenge") {
    if state.js_detector.is_cookie_valid(cookie_val, &src_ip.to_string()) {
        packet.js_challenge_passed = true;  // CaptchaDetector가 이 값을 읽음
    }
}
```

이 플래그가 없으면 CaptchaDetector가 JS Challenge를 통과하지 않은 요청에도 CAPTCHA를 요구한다. 아래 설명 참조.

---

## 13. Detector 9 — CAPTCHA

### 역할

JS Challenge를 통과한 요청에 대해 추가로 사람인지 검증한다. reCAPTCHA v2를 사용하지만 WAF 서버 자체는 Google API를 호출하지 않는다.

### JS Challenge와의 연계 (핵심 설계)

```rust
fn detect(&self, packet: &Packet) -> DetectionResult {
    if packet.captcha_passed { return pass(); }

    // CAPTCHA 쿠키 확인 (위변조/만료는 JS 상태 무관하게 처리)
    if let Some(cookie) = packet.cookie.get(CAPTCHA_COOKIE) {
        return match verify(cookie, ip) {
            Ok(true)  => pass(),
            Ok(false) => captcha("expired"),
            Err(r)    => block("tampered"),
        };
    }

    // JS Challenge 미통과 → CAPTCHA 요구하지 않고 Pass
    // (파이프라인에서 JsChallengeDetector가 먼저 처리)
    if !packet.js_challenge_passed {
        return pass();  ← 핵심 라인
    }

    // JS는 통과했지만 CAPTCHA 없음 → CAPTCHA 발급
    captcha("no valid token or cookie")
}
```

**왜 이 로직이 필요한가?**

파이프라인은 우선순위가 높은 결과를 선택한다 (`Captcha > Challenge`). 만약 이 로직이 없으면:
- JsChallengeDetector → Challenge (쿠키 없음)
- CaptchaDetector → Captcha (쿠키 없음)
- 파이프라인 → Captcha 선택 (더 높은 우선순위)

신규 브라우저는 JS Challenge를 건너뛰고 바로 CAPTCHA를 받게 된다. 올바른 흐름은:
1. JS Challenge (봇 1차 필터)
2. JS Challenge 통과 후 CAPTCHA (사람 확인)

### 폐쇄망 호환 구조

```
[클라이언트 브라우저]
       │
       │ GET /__waf/captcha/verify (WAF가 생성한 HTML)
       ├──→ https://www.google.com/recaptcha/api.js 로드 (브라우저 직접)
       │        ↓ reCAPTCHA 위젯 렌더링
       │        ↓ 사람이 풀기
       │        ↓ Google이 토큰 생성 (브라우저 직접)
       ├──→ POST /__waf/captcha/verify (토큰 포함)
       │
[WAF rust-engine]
       │ 토큰 존재 여부 + 길이(>20자) 만 확인
       │ Google API 호출 없음
       └──→ 통과 시 자체 서명 쿠키 발급
```

WAF 서버는 인터넷 연결이 없어도 동작한다. 클라이언트 브라우저가 Google과 직접 통신한다. 이 구조 덕분에 내부망(폐쇄망)에서도 배포 가능하다.

단, 완전한 보안을 원한다면 Google의 서버측 토큰 검증 API를 호출해야 한다. 현재 구현은 토큰 존재 여부만 확인한다.

---

## 14. 응답 생성 — challenge/mod.rs

### JS Challenge HTML

```rust
pub fn js_challenge_response(original_uri: &str) -> Response {
    let escaped = html_escape(original_uri);  // XSS 방어
    let html = format!(r#"
        <form id="f" method="POST" action="/__waf/js-challenge/verify">
          <input type="hidden" name="original_uri" value="{escaped}">
          <input type="hidden" name="screen-width" id="sw">
          <input type="hidden" name="screen-height" id="sh">
        </form>
        <script>
          document.getElementById('sw').value=window.innerWidth;
          document.getElementById('sh').value=window.innerHeight;
          document.getElementById('f').submit();
        </script>
    "#);
}
```

페이지를 받은 브라우저는 JS를 실행해서 화면 크기를 폼에 채우고 즉시 POST한다. 사용자 눈에는 깜빡임 없이 자동으로 진행된다.

`window.innerWidth/Height`가 0이면 JS를 실행하지 못한 것이므로 verify에서 400을 반환한다.

### XSS 방어 — html_escape

```rust
fn html_escape(s: &str) -> String {
    for c in s.chars() {
        match c {
            '&' => "&amp;",   '<' => "&lt;",   '>' => "&gt;",
            '"' => "&quot;",  '\'' => "&#x27;",
            _ => c
        }
    }
}
```

`original_uri`를 HTML 속성값에 직접 넣기 때문에 이스케이프가 필수다. 공격자가 `original_uri="><script>alert(1)</script>`처럼 보내면 XSS가 된다. 이스케이프로 방어한다.

### 오픈 리다이렉트 방어

```rust
fn safe_redirect(uri: &str) -> &str {
    if uri.starts_with('/') { uri } else { "/" }
}
```

`original_uri=https://evil.com`처럼 외부 URL이 들어오면 `/`로 리다이렉트한다. 쿠키 발급 후 외부 사이트로 보내는 피싱 공격을 막는다.

---

## 15. 메인 서버 — main.rs

### AppState

```rust
#[derive(Clone)]
struct AppState {
    pipeline:         Arc<Pipeline>,              // 탐지 파이프라인
    kafka:            Arc<KafkaProducer>,          // Kafka 프로듀서
    cfg:              Arc<config::Config>,         // 환경변수 설정
    js_detector:      Arc<JsChallengeDetector>,   // 쿠키 검증용
    captcha_detector: Arc<CaptchaDetector>,       // 쿠키 발급용
    http_client:      Client<HttpConnector, ...>, // upstream 프록시 클라이언트
}
```

`Arc<T>`로 감싸서 여러 스레드가 복사 없이 공유한다. `Clone`을 derive해서 axum이 각 요청마다 state를 clone할 때 비용이 거의 들지 않는다 (Arc는 포인터 복사).

### 라우터

```rust
Router::new()
    .route("/__waf/health",               get(health_handler))
    .route("/__waf/js-challenge/verify",  post(js_verify_handler))
    .route("/__waf/captcha/verify",       post(captcha_verify_handler))
    .fallback(proxy_handler)  // 나머지 모든 경로
```

`/__waf/` 경로는 WAF 내부 엔드포인트다. 그 외 모든 경로는 `proxy_handler`가 받아서 탐지 파이프라인을 실행한다.

`.fallback()`을 쓴 이유: `/{*path}` 와일드카드 라우트는 axum 테스트에서 패닉을 일으키는 버그가 있었다. `.fallback()`은 이 문제가 없고 더 명시적이다.

### proxy_handler 흐름

```rust
async fn proxy_handler(State(state), ConnectInfo(peer), req: Request) -> Response {
    // 1. 바디 수집
    let body_bytes = body.collect().await?.to_bytes();

    // 2. Request → Packet
    let mut packet = build_packet(&parts, src_ip, &body_bytes);

    // 3. JS 쿠키 전처리
    if let Some(v) = packet.cookie.get("waf_js_challenge") {
        if state.js_detector.is_cookie_valid(v, &ip) {
            packet.js_challenge_passed = true;
        }
    }

    // 4. 파이프라인 실행
    let result = state.pipeline.run(&packet);

    // 5. Action에 따른 응답
    match result.action {
        Pass      → proxy_upstream(...)
        Block     → send_kafka(); block_response(reason)
        Challenge → send_kafka(); js_challenge_response(uri)
        Captcha   → send_kafka(); captcha_response(uri, site_key)
    }
}
```

### 역방향 프록시 (proxy_upstream)

```rust
async fn proxy_upstream(state, parts, body_bytes) -> Response {
    let upstream_uri = format!("{}{}", cfg.upstream_url, path_and_query);

    // hop-by-hop 헤더 제거 (Connection, Transfer-Encoding 등)
    for hop in ["connection", "keep-alive", "transfer-encoding", ...] {
        headers.remove(hop);
    }

    // upstream으로 요청 그대로 전달
    let resp = http_client.request(upstream_req).await?;

    // upstream 응답도 hop-by-hop 제거 후 클라이언트에 반환
    Response::from_parts(resp_parts, Body::from(resp_bytes))
}
```

hop-by-hop 헤더는 프록시 구간에서만 유효한 헤더다. 이걸 제거하지 않으면 `Transfer-Encoding: chunked`가 통과해서 응답이 깨진다.

### Kafka 비동기 전송

```rust
fn send_kafka_event(state, src_ip, uri, reason, confidence, action) {
    let kafka = Arc::clone(&state.kafka);
    tokio::spawn(async move {          // 별도 태스크로 분리
        kafka.send(&event).await;
    });
}
```

Kafka 전송을 응답 경로에서 분리한다. Kafka가 느리거나 죽어있어도 WAF 응답 레이턴시에 영향이 없다.

---

## 16. Kafka 이벤트 스트리밍

### 이벤트 구조

```json
{
  "timestamp": 1700000000,
  "src_ip": "1.2.3.4",
  "uri": "/login",
  "detector": "pipeline",
  "action": "Block",
  "reason": "IP rate limit exceeded. violations: 2",
  "confidence": 1.0
}
```

### 전송 조건

- Block, Challenge, Captcha → 전송
- Pass → 전송 안 함

Pass는 정상 트래픽이므로 전송하면 Kafka 부하가 너무 크다.

### 파티셔닝

```rust
FutureRecord::to(&self.topic)
    .payload(payload.as_bytes())
    .key(event.src_ip.as_str())  // src_ip를 파티션 키로 사용
```

동일 IP의 이벤트가 항상 같은 파티션으로 간다. 이벤트 순서를 보장하고, 하나의 IP에 대한 이벤트 스트림을 분석할 때 하나의 컨슈머만 처리하면 된다.

### Kafka 설정

```rust
ClientConfig::new()
    .set("message.timeout.ms", "5000")      // 5초 타임아웃
    .set("queue.buffering.max.ms", "100")   // 100ms 배치 버퍼링
    .set("compression.type", "lz4")         // lz4 압축
```

`queue.buffering.max.ms=100`은 이벤트를 100ms 동안 모아서 배치로 전송한다는 설정이다. 개별 전송보다 네트워크 효율이 좋다.

---

## 17. 동시성 모델

### tokio 런타임

```
물리 CPU 코어 수만큼 worker thread 생성
각 thread는 tokio 이벤트 루프 실행
I/O 대기 중 다른 task 처리 (비동기)
```

`#[tokio::main]`이 달린 main 함수가 tokio 런타임을 시작한다. `async fn proxy_handler`는 각 HTTP 요청마다 하나의 task로 실행된다.

### 상태 공유

```
Arc<Pipeline>         읽기 전용 공유 → 락 없음
Arc<KafkaProducer>    내부적으로 thread-safe
Arc<Config>           읽기 전용 공유 → 락 없음
DashMap(ip_entries)   샤드 락으로 동시 쓰기 허용
```

탐지 파이프라인 자체는 읽기 전용이다. 상태를 갖는 건 각 Detector의 내부 DashMap들뿐이다. DashMap은 전체 맵에 락을 걸지 않고 특정 키의 샤드에만 락을 건다.

### 메모리 레이아웃

```
요청 당 할당:
  - Packet 구조체 (스택 + 일부 힙)
  - HTTP 요청 바디 (bytes::Bytes, 레퍼런스 카운팅)
  - 응답 바디

공유 (락 없이 읽기):
  - 파이프라인, Detector 인스턴스 (Arc)
  - Config

공유 (DashMap):
  - IP rate counter
  - JS 챌린지 발급 쿠키 (실제로는 저장 안 하고 검증만)
  - Credential stuffing counter
```

---

## 18. 보안 설계 포인트

### 1. 쿠키 IP 바인딩

발급된 쿠키는 발급 IP에만 유효하다. 공격자가 다른 사람의 쿠키를 훔쳐와도 자신의 IP에서는 쓸 수 없다.

### 2. 쿠키 서명

쿠키를 조작하면 서명 검증에서 실패하고, 실패 시 Challenge가 아닌 **Block**을 내린다. 의도적인 쿠키 위조 시도는 즉시 차단한다.

### 3. XSS 방어

모든 HTML 응답에서 사용자 입력(`original_uri` 등)은 `html_escape()`를 거친다.

### 4. 오픈 리다이렉트 방어

리다이렉트 목적지가 `/`로 시작하지 않으면 무조건 `/`로 보낸다.

### 5. hop-by-hop 헤더 필터링

프록시를 거치면서 `Transfer-Encoding`, `Connection` 같은 헤더가 downstream으로 넘어가면 HTTP 스펙 위반이 된다.

### 현재 구현의 한계

- CAPTCHA 서버측 검증 없음 (토큰 길이만 확인)
- JS 쿠키 서명이 XOR 기반 (운영 환경에서는 HMAC-SHA256 권장)
- `JS_TOKEN_SECRET` 기본값 사용 시 경고는 내지만 계속 실행됨

---

## 19. 테스트 전략

### 단위 테스트 (각 Detector 파일)

각 Detector는 자체 테스트를 가진다. `Packet`을 직접 만들어서 `detect()`를 호출하고 결과를 검증한다.

```rust
#[test]
fn blocks_on_threshold_exceeded() {
    let limiter = IpRateLimiter::new();
    let p = make_packet("1.2.3.5");
    for _ in 0..THRESHOLD {
        limiter.detect(&p);  // 10번
    }
    let result = limiter.detect(&p);  // 11번째
    assert!(result.is_block());
}
```

### 통합 테스트 (main.rs)

실제 axum 앱을 메모리에 띄우고 HTTP 요청을 보내서 엔드-투-엔드로 테스트한다.

```rust
fn test_app(state: AppState) -> Router {
    Router::new()
        .route("/__waf/health", get(health_handler))
        ...
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
}

#[tokio::test]
async fn proxy_block_action_returns_403() {
    let mut state = base_state();
    state.pipeline = Arc::new(Pipeline::new(vec![Box::new(AlwaysBlock)]));

    let resp = test_app(state)
        .oneshot(Request::builder().uri("/attack").body(Body::empty()).unwrap())
        .await.unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
```

`MockConnectInfo`는 실제 TCP 연결 없이 IP를 주입하는 axum 테스트 유틸리티다. `oneshot()`은 요청을 앱에 한 번 전달하고 응답을 받는다.

### waf-tester (시스템 테스트)

실제 Docker 스택에 HTTP 요청을 보내는 블랙박스 테스트 도구다. 총 6개 시나리오로 탐지율 100%를 검증한다.

```
시나리오 1: 정상 브라우저 → JS Challenge (200)
시나리오 2: 봇 UA → Block (403)
시나리오 3: Rate Limit 12회 → Block (403)
시나리오 4: 헤더 없는 요청 → Challenge/Block
시나리오 5: 로그인 7회 → Block (403)
시나리오 6: 분산 credential stuffing → Block/Captcha
```

---

## 20. 설계 결정과 트레이드오프

### Rust를 쓴 이유

- 메모리 안전성을 컴파일 타임에 보장
- GC pause 없는 예측 가능한 레이턴시
- zero-copy, 참조 기반 설계가 언어 수준에서 강제됨
- C++ WAF 10년 경험을 Rust의 소유권 모델로 자연스럽게 번역 가능

### DashMap vs Mutex<HashMap>

DashMap은 맵을 N개 샤드로 나눠서 각 샤드에 별도 RwLock을 건다. 서로 다른 IP는 대부분 다른 샤드에 속하므로 동시 요청 처리 시 경합이 적다.

`Mutex<HashMap>`을 쓰면 모든 요청이 단일 락을 놓고 경쟁한다. 100 RPS에서 99개 요청이 1개를 기다린다.

### 단일 프로세스 vs 멀티 프로세스

현재 구현은 단일 프로세스다. Rate Limit 카운터가 메모리에 있어서 프로세스가 재시작되면 초기화된다.

멀티 프로세스(nginx worker 스타일)로 확장하려면 `shared_memory/mod.rs`를 구현해서 프로세스 간 카운터를 공유해야 한다. 현재는 이 파일이 `todo!()`로 비어있다.

### Pipeline early exit

Block에만 early exit을 적용했다. Challenge와 Captcha는 계속 실행한다. 만약 Challenge도 early exit을 하면, IpRateLimiter가 Pass, UserAgent가 Challenge를 반환할 때 HeaderFingerprint가 Block을 반환할 기회를 잃는다. 파이프라인 후반부의 더 심각한 탐지를 놓치지 않기 위한 설계다.

### Kafka 비동기 전송

`tokio::spawn`으로 분리해서 Kafka 전송이 응답 레이턴시에 영향을 주지 않는다. 단, Kafka 전송 실패 시 경고 로그만 남기고 무시한다. 이벤트 유실이 허용되는 트레이드오프다. 이벤트 보장이 필요하면 채널 버퍼를 두거나 WAL을 사용해야 한다.
