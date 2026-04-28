# mini-protection

Rust로 구현한 봇 탐지 리버스 프록시 WAF.  
OpenResty(nginx) → rust-engine → Gitea 구조로 AWS EC2에 배포.

## Architecture

```
Client
  │
  ▼ :80  → 301 HTTPS 리다이렉트
  ▼ :443 (TLS 1.2/1.3, Let's Encrypt 와일드카드)
OpenResty (nginx)
  ├─ waf.orhskim.duckdns.org
  │     ssl_client_hello_by_lua: JA3 계산 → ngx.ctx
  │     access_by_lua: X-JA3-Fingerprint 헤더 삽입
  │     → rust-engine:8080
  └─ viewer.orhskim.duckdns.org → event-viewer:8081

rust-engine:8080
  Packet 파싱 → Detection Pipeline
    ├─ Pass    → backend:3000 (Gitea)
    ├─ Block   → 403 HTML
    ├─ Challenge → JS Challenge HTML
    └─ Captcha → reCAPTCHA HTML
  탐지 이벤트 → Kafka (mini-protection-events)
                   └─ event-viewer (웹 대시보드)
```

| 컴포넌트 | 역할 |
|----------|------|
| **OpenResty** | TLS 종단, JA3 TLS 지문 추출, rust-engine 프록시 |
| **rust-engine** | Packet 파싱 → 탐지 파이프라인 → 응답 결정 |
| **backend (Gitea)** | 실제 서비스. Pass된 요청만 도달 |
| **event-viewer** | Kafka 이벤트 실시간 웹 대시보드 |
| **Kafka** | 탐지 이벤트 비동기 스트리밍 |

## Detection Pipeline

우선순위: `Block > Captcha > Challenge > Pass`. Block 시 early exit.

### 1. HoneypotDetector
HTML 응답에 숨겨진 링크(`/__mini-protection/trap`) 삽입. 봇이 접근하면 해당 IP 영구 Block.

### 2. IP Rate Limiter

| 설정 | 값 |
|------|----|
| 윈도우 | 60초 |
| 임계값 | 30회 초과 시 Block |
| 누적 차단 | 1분 → 5분 → 30분 → 영구 |

### 3. PathScannerDetector
`.env`, `.git`, `wp-admin`, `phpmyadmin`, `xmlrpc.php` 등 취약점 열거 경로 Block.

### 4. JA3 Fingerprint
TLS ClientHello에서 추출한 JA3 해시 기반 탐지.

| 조건 | Action |
|------|--------|
| 헤더 없음 | Pass |
| 알려진 봇 JA3 (python-requests, curl) | Block |
| 브라우저 UA + 화이트리스트 JA3 | Pass |
| 브라우저/알 수 없는 UA + 미등록 JA3 | Challenge |

### 5. User-Agent Detection

- **Block**: `python-requests`, `curl`, `wget`, `scrapy`, `go-http-client`, `java/`, `okhttp`, `bot`, `crawler`, `spider`, `selenium`, `nikto`, `sqlmap` 등
- **Pass**: Chrome, Firefox, Safari, Edge
- **Challenge**: 그 외

### 6. Header Fingerprint (점수제)

| 조건 | 점수 |
|------|------|
| `Accept: */*` | +30 |
| `Accept-Language` 없음 | +30 |
| `Accept-Encoding` 없음 | +20 |
| `Connection: close` | +20 |

0–30: Pass / 31–60: Challenge / 61+: Block

### 7. Credential Stuffing

로그인 엔드포인트(`/login`, `/signin`, `/auth` 등):

| 조건 | Action |
|------|--------|
| 동일 IP 5회/분 초과 | Block (5분) |
| 동일 username을 3개+ IP에서 시도 | Block |

### 8. JS Challenge

| 조건 | Action |
|------|--------|
| 쿠키 없음 | Challenge (JS 폼 자동 제출) |
| 유효한 쿠키 | Pass |
| 위변조/IP 불일치 쿠키 | Block |
| 만료된 쿠키 (1시간) | Challenge |

### 9. Captcha

JS Challenge 통과 후 적용. `CAPTCHA_SITE_KEY` 없으면 Pass로 우회.

## How to Run

```bash
cp .env.example .env  # JS_TOKEN_SECRET 설정
docker compose up --build
```

### 환경변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `JS_TOKEN_SECRET` | `change-me-in-production` | JS Challenge 쿠키 서명 키 |
| `CAPTCHA_SITE_KEY` | *(선택)* | reCAPTCHA v2 사이트 키 |
| `SERVER_DOMAIN` | `waf.orhskim.duckdns.org` | Gitea 도메인 |

```bash
echo "JS_TOKEN_SECRET=$(openssl rand -hex 32)" > .env
```

## How to Test

```bash
# 헬스체크
curl https://waf.orhskim.duckdns.org/__mini-protection/health

# 봇 UA → Block
curl -v -H "User-Agent: python-requests/2.31.0" https://waf.orhskim.duckdns.org

# 정상 브라우저 → JS Challenge
curl -v \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0" \
  -H "Accept: text/html,application/xhtml+xml,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  https://waf.orhskim.duckdns.org

# Kafka 이벤트 확인
docker compose exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic mini-protection-events \
  --from-beginning
```

## Adding a Detector

```
1. rust-engine/src/detectors/<name>.rs 생성
2. Detector trait 구현
3. rust-engine/src/main.rs Pipeline::new()에 등록
```

## Deploy (AWS EC2)

```bash
# EC2에서
cd /opt/mini-protection
git pull
docker compose up -d --build

# rust-engine 재배포 후 nginx DNS 재조회 필요
docker compose restart nginx
```
