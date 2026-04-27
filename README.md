# mini-protection

Rust로 구현한 봇 탐지 리버스 프록시.

## Architecture

```
  Client
    │
    ▼
  nginx:80          TLS termination, X-Real-IP 삽입
    │
    ▼
  rust-engine:8080
    │
    ├─ Packet 파싱
    │
    ▼
  Detection Pipeline
    ├─ IpRateLimiter
    ├─ UserAgentDetector
    ├─ HeaderFingerprint
    ├─ CredentialStuffing
    ├─ JsChallenge
    └─ Captcha
         │
         ├─ Pass → backend:80
         └─ Block / Challenge / Captcha → 응답 반환 (403 / HTML)
                                               │
                                             Kafka (waf-events)
```

| 컴포넌트 | 역할 |
|----------|------|
| **nginx** | 클라이언트 연결 수락, `X-Real-IP` 삽입, rust-engine으로 프록시 |
| **rust-engine** | Packet 파싱 → 탐지 파이프라인 → Pass / Block / Challenge / Captcha 결정 |
| **backend** | 실제 애플리케이션 서버. Pass된 요청만 도달 |
| **Kafka** | 탐지 이벤트(`waf-events`) 비동기 스트리밍 |

## Detection Pipeline

파이프라인은 Detector를 순서대로 실행하고 가장 높은 우선순위 Action을 최종 결과로 선택한다.

**우선순위**: `Block > Captcha > Challenge > Pass`

Block이 발생하면 이후 Detector는 실행하지 않는다 (early exit).

### 1. IP Rate Limiting

| 설정 | 값 |
|------|----|
| 윈도우 | 60초 |
| 임계값 | 10회/분 초과 시 Block |
| 차단 정책 | 누적: 1분 → 5분 → 30분 → 영구 차단 |

### 2. User-Agent Detection

- **Block**: `python-requests`, `curl`, `wget`, `scrapy`, `go-http-client`, `java/`, `okhttp`, `\bbot\b` 등
- **Pass**: Chrome, Firefox, Safari, Edge (Mozilla/5.0 기반 패턴)
- **Challenge**: 그 외 알 수 없는 UA

### 3. Header Fingerprint

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

로그인 엔드포인트(`/login`, `/signin`, `/auth`, `/api/login` 등):

| 조건 | Action |
|------|--------|
| 동일 IP에서 5회/분 초과 | Block (5분) |
| 동일 username을 3개 이상 다른 IP에서 시도 | Captcha |

### 5. JS Challenge

| 조건 | Action |
|------|--------|
| 쿠키 없음 | Challenge (JS 폼 자동 제출) |
| 유효한 쿠키 | Pass |
| 위변조된 쿠키 | Block |
| 만료된 쿠키 | Challenge (재발급) |

쿠키 TTL: 1시간. 서명: IP + timestamp 바인딩.

### 6. Captcha

JS Challenge를 통과한 요청에만 적용.

| 조건 | Action |
|------|--------|
| 유효한 쿠키 없음 | Captcha (reCAPTCHA v2 HTML) |
| 위변조된 쿠키 | Block |

`CAPTCHA_SITE_KEY` 환경변수가 없으면 위젯 없이 동작한다.

## How to Run

```bash
docker compose up --build
```

### 환경변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `LISTEN_ADDR` | `0.0.0.0:8080` | WAF 리슨 주소 |
| `UPSTREAM_URL` | `http://backend:80` | 백엔드 URL |
| `KAFKA_BROKERS` | `kafka:9092` | Kafka 브로커 |
| `KAFKA_TOPIC` | `waf-events` | 이벤트 토픽 |
| `JS_TOKEN_SECRET` | *(운영 전 반드시 변경)* | JS 챌린지 쿠키 서명 키 |
| `CAPTCHA_SITE_KEY` | *(선택)* | reCAPTCHA v2 사이트 키 |

운영 환경에서는 `.env` 파일로 관리:

```bash
echo "JS_TOKEN_SECRET=$(openssl rand -hex 32)" > .env
```

## How to Test

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

## Adding a Detector

```
1. rust-engine/src/detectors/<name>.rs 생성
2. Detector trait 구현
3. src/main.rs의 Pipeline::new() 벡터에 추가
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
