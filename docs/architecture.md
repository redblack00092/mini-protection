# WAF Architecture

## Overview

```
Client → nginx:80 → rust-engine:8080 → backend:80
                          │
                          ▼
                       Kafka (waf-events)
```

## Request Flow

1. **nginx** — TLS termination, load balancing, `X-Real-IP` / `X-Forwarded-For` 삽입
2. **rust-engine** — Packet 파싱 → Pipeline 실행 → Pass/Challenge/Captcha/Block 결정
3. **backend** — 실제 애플리케이션 서버 (Pass된 요청만 도달)
4. **Kafka** — 모든 탐지 이벤트를 `waf-events` 토픽으로 비동기 전송

## Pipeline

```
Packet
  ├─ IpRateLimiter       (IP당 요청 빈도 제한)
  ├─ UserAgentDetector   (알려진 봇 UA 탐지)
  ├─ HeaderFingerprint   (헤더 지문 기반 봇 식별)
  ├─ CredentialStuffing  (로그인 엔드포인트 공격 탐지)
  ├─ JsChallenge         (JS 실행 가능 여부 검증)
  └─ Captcha             (CAPTCHA 풀이 검증)
```

## Action Priority

`Block > Captcha > Challenge > Pass`

파이프라인은 모든 Detector를 실행한 후 가장 높은 우선순위 Action을 최종 처분으로 선택한다.

## Shared Memory

프로세스 재시작 없이 카운터/블록리스트를 유지하기 위해 `shared_memory` crate로 named shared memory region을 사용한다.
