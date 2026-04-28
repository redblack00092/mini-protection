# WAF Architecture

## Overview

```
Client → nginx:80/443 → rust-engine:8080 → backend:8080 (go-httpbin)
                              │
                              ▼
                       Kafka (mini-protection-events)
                              │
                              ▼
                  event-viewer:8081 (Flask)
```

## Request Flow

1. **nginx (OpenResty)** — TLS termination, JA3 지문 계산(Lua), Docker DNS resolver를 통한 stale-cache 방지, `X-Real-IP` / `X-JA3-Fingerprint` 삽입
2. **rust-engine** — Packet 파싱 → Pipeline 실행 → Pass/Challenge/Captcha/Block 결정
3. **backend** — `mccutchen/go-httpbin` 컨테이너(8080), Pass된 요청만 도달
4. **Kafka** — 모든 탐지 이벤트를 `mini-protection-events` 토픽으로 비동기 전송 (Pass 제외)
5. **event-viewer** — Flask + Kafka consumer, 최근 200건 in-memory deque, https://viewer.orhskim.duckdns.org 에서 조회

## Pipeline

```
Packet
  ├─ HoneypotDetector        (숨겨진 링크 접근 봇 영구차단)
  ├─ IpRateLimiter           (IP당 요청 빈도 제한)
  ├─ PathScannerDetector     (취약점 열거 경로 차단)
  ├─ Ja3FingerprintDetector  (TLS 지문 기반 봇 식별 — nginx JA3 모듈 필요)
  ├─ UserAgentDetector       (알려진 봇 UA 탐지)
  ├─ HeaderFingerprint       (헤더 지문 기반 봇 식별)
  ├─ CredentialStuffing      (로그인 엔드포인트 공격 탐지)
  ├─ JsChallenge             (JS 실행 가능 여부 검증)
  └─ Captcha                 (CAPTCHA 풀이 검증)
```

## Action Priority

`Block > Captcha > Challenge > Pass`

파이프라인은 모든 Detector를 실행한 후 가장 높은 우선순위 Action을 최종 처분으로 선택한다.

## Shared State

- `IpRateLimiter`: `DashMap<IpAddr, IpEntry>` — 요청 카운터, 위반 횟수, 차단 시각
- `HoneypotDetector`: `Arc<DashMap<IpAddr, ()>>` — 트랩에 걸린 IP 집합 (main과 공유)
- `CredentialStuffingDetector`: `DashMap<IpAddr, IpLoginEntry>` + `DashMap<String, UsernameEntry>` — IP별/username별 로그인 시도 추적

## 성능 원칙

`/docs/performance.md` 참고. 주요 항목:
- Packet은 파이프라인 전체에서 `&Packet`으로 참조 전달 (zero-copy)
- HTTP body는 `Bytes` (Arc 기반 공유 버퍼) — 매 요청 Vec alloc 회피
- DashMap entry API 사용으로 lock 전환 최소화
- DetectionResult.reason은 String이지만 Block/Challenge 발생 시에만 alloc
