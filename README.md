# WAF Bot Detection Engine

Rust로 구현한 고성능 봇 탐지 리버스 프록시. 10년간의 C++ WAF 개발 경험을 기반으로 설계했다.

## Overview

```
                    ┌─────────────────────────────────────────────┐
  Client ──────────▶│  nginx:80                                   │
                    │  (TLS termination, X-Real-IP 삽입)          │
                    └─────────────┬───────────────────────────────┘
                                  │
                    ┌─────────────▼───────────────────────────────┐
                    │  rust-engine:8080                           │
                    │                                             │
                    │  Packet 파싱                                 │
                    │     │                                       │
                    │     ▼                                       │
                    │  Detection Pipeline                         │
                    │  ├─ IpRateLimiter                           │
                    │  ├─ UserAgentDetector                       │
                    │  ├─ HeaderFingerprint                       │
                    │  ├─ CredentialStuffing                      │
                    │  ├─ JsChallenge                             │
                    │  └─ Captcha                                 │
                    │     │                                       │
                    │     ▼                                       │
                    │  Block / Challenge / Captcha / Pass         │
                    └──────┬──────────────────┬───────────────────┘
                           │ Pass             │ Block/Challenge/Captcha
                           │                 ▼
                    ┌──────▼──────┐   응답 반환 (403 / HTML)
                    │ backend:80  │
                    └─────────────┘
                           │
                    ┌──────▼──────┐
                    │   Kafka     │  waf-events 토픽
                    │  (비동기)   │  Block/Challenge/Captcha 이벤트
                    └─────────────┘
```

## Architecture

| 컴포넌트 | 역할 |
|----------|------|
| **nginx** | 클라이언트 연결 수락, `X-Real-IP` 삽입, rust-engine으로 프록시 |
| **rust-engine** | Packet 파싱 → 탐지 파이프라인 실행 → Pass/Block/Challenge/Captcha 결정 |
| **backend** | 실제 애플리케이션 서버. Pass된 요청만 도달 |
| **Kafka** | 탐지 이벤트(`waf-events`)를 비동기 스트리밍. SIEM/분석 시스템과 연동 |

## Detection Pipeline

파이프라인은 모든 Detector를 순서대로 실행하고 가장 높은 우선순위 Action을 최종 결과로 선택한다.

**우선순위**: `Block > Captcha > Challenge > Pass`

Block이 발생하면 이후 Detector는 실행하지 않는다 (early exit).

### 1. IP Rate Limiting

| 설정 | 값 |
|------|----|
| 윈도우 | 60초 |
| 임계값 | 10회/분 초과 시 Block |
| 차단 정책 | 누적: 1분 → 5분 → 30분 → 영구 차단 |

### 2. User-Agent Detection

**블랙리스트** (Block): `python-requests`, `curl`, `wget`, `scrapy`, `go-http-client`, `java/`, `okhttp`, `\bbot\b` 등

**화이트리스트** (Pass): Chrome, Firefox, Safari, Edge (Mozilla/5.0 기반 패턴)

그 외 알 수 없는 UA → Challenge

### 3. Header Fingerprint

헤더 패턴에 점수를 부여하고 임계값으로 판정한다.

| 조건 | 점수 |
|------|------|
| `Accept: */*` | +30 |
| `Accept-Language` 없음 | +30 |
| `Accept-Encoding` 없음 | +20 |
| `Connection: close` | +20 |

| 점수 | Action |
|------|--------|
| 0–30 | Pass |
| 31–60 | Challenge |
| 61+ | Block |

### 4. Credential Stuffing

로그인 엔드포인트(`/login`, `/signin`, `/auth`, `/api/login` 등)에 대해:

| 조건 | Action |
|------|--------|
| 동일 IP에서 5회/분 초과 | Block (5분) |
| 동일 username을 3개 이상 다른 IP에서 시도 | Captcha |

### 5. JS Challenge

JS를 실행할 수 없는 봇을 걸러낸다.

- 쿠키 없음 → Challenge (JS 폼 자동 제출, `window.innerWidth/Height` 수집)
- 유효한 쿠키 → Pass
- 위변조된 쿠키 → Block
- 만료된 쿠키 → Challenge (재발급)

쿠키 TTL: 1시간. 서명: IP + timestamp 바인딩.

### 6. CAPTCHA

JS Challenge를 통과한 요청에만 적용된다.

- 유효한 쿠키 없음 → Captcha (reCAPTCHA v2 HTML 응답)
- 위변조된 쿠키 → Block

**폐쇄망 호환**: WAF 서버 자체는 Google API를 호출하지 않는다. reCAPTCHA JS를 포함한 HTML을 생성해서 클라이언트 브라우저에 응답하고, 브라우저가 Google과 직접 통신한다. `CAPTCHA_SITE_KEY` 환경변수가 없으면 위젯 없이 동작한다.

## Technical Highlights

- **zero-copy Packet**: `Packet` 구조체는 파이프라인 전체를 `&` 참조로만 전달, 복사 없음
- **Detector trait**: `detect(&Packet) -> DetectionResult` 단일 인터페이스로 탐지 모듈 추가/제거 가능
- **단일 프로세스 멀티스레드**: DashMap으로 lock 전환 최소화, Arc<T>로 상태 공유
- **Kafka 비동기 스트리밍**: Block/Challenge/Captcha 이벤트만 전송 (Pass 제외)
- **HMAC 쿠키 바인딩**: JS/CAPTCHA 쿠키는 발급 IP에 바인딩되어 다른 IP에서 재사용 불가

## 탐지 모듈 추가 방법

```
1. rust-engine/src/detectors/<name>.rs 생성
2. Detector trait 구현
3. src/main.rs의 Pipeline::new() 벡터에 추가
```

## How to Run

```bash
docker compose up --build
```

**환경변수** (docker-compose.yml):

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `LISTEN_ADDR` | `0.0.0.0:8080` | WAF 리슨 주소 |
| `UPSTREAM_URL` | `http://backend:80` | 백엔드 URL |
| `KAFKA_BROKERS` | `kafka:9092` | Kafka 브로커 |
| `KAFKA_TOPIC` | `waf-events` | 이벤트 토픽 |
| `JS_TOKEN_SECRET` | *(운영 전 반드시 변경)* | JS 챌린지 쿠키 서명 키 |
| `CAPTCHA_SITE_KEY` | *(선택)* | reCAPTCHA v2 사이트 키 |

## How to Test

### mini-protection-tester (권장)

6개 시나리오를 자동 실행하고 탐지율을 리포트하는 별도 CLI 툴.
→ [mini-protection-tester](https://github.com/YOUR_USERNAME/mini-protection-tester)

```bash
git clone https://github.com/YOUR_USERNAME/mini-protection-tester
cd mini-protection-tester
cargo run -- http://localhost
```

```
══════════════════════════════════════════════════════════════════════
  WAF Bot Detection 검증 리포트
══════════════════════════════════════════════════════════════════════
#   시나리오                                         기대     실제   응답(ms)  결과
──────────────────────────────────────────────────────────────────────
1   정상 브라우저 → 200 (JS Challenge)                200    200        1  PASS
2   봇 UA → 403 Block                            403    403        1  PASS
3   Rate Limit 초과 → 403 Block                   403    403       11  PASS
4   헤더 없는 요청 → Challenge/Block 탐지               403    403        0  PASS
5   로그인 엔드포인트 반복 → 403 Block                    403    403        6  PASS
6   분산 username 공격 → Captcha/Block              200    200        3  PASS
──────────────────────────────────────────────────────────────────────
탐지율: 6/6 (100%)
```

특정 시나리오만 실행:

```bash
cargo run -- http://localhost -s 1,2,3
```

### curl

```bash
# 헬스체크
curl http://localhost/__waf/health

# 봇 UA → 403 Block
curl -v -H "User-Agent: python-requests/2.31.0" http://localhost

# 정상 브라우저 → JS Challenge HTML
curl -v \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0" \
  -H "Accept: text/html,application/xhtml+xml,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  http://localhost

# Rate Limit 테스트 (10회 초과 시 Block)
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "req $i: %{http_code}\n" \
    -H "User-Agent: Mozilla/5.0 Chrome/124.0" \
    http://localhost
done

# Kafka 이벤트 확인
docker compose exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic waf-events \
  --from-beginning \
  --max-messages 10
```

## Deploy (AWS EC2)

`deploy/EC2_GUIDE.md` 참조.

```bash
# EC2 초기 설정 (인스턴스에서 한 번만)
export REPO_URL=https://github.com/YOUR_USERNAME/mini-protection.git
export JS_TOKEN_SECRET=$(openssl rand -hex 32)
bash -s < deploy/setup-ec2.sh

# 이후 업데이트
./deploy/deploy.sh <EC2_PUBLIC_IP> --pem <pem-file>
```

