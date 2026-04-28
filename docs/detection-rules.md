# Detection Rules

## HoneypotDetector

| 조건 | Action |
|------|--------|
| HTML 응답에 숨겨진 `/__mini-protection/trap` 링크 주입 | - |
| 해당 경로 접근 → IP를 HoneypotStore에 기록 | - |
| HoneypotStore에 등록된 IP의 모든 요청 | Block (confidence 1.0) |

트랩 엔드포인트는 404 반환 (스마트 봇의 탐지 회피 방지).

## IpRateLimiter

| 조건 | Action |
|------|--------|
| 60초 윈도우 내 요청 수 > 30 | Block |
| 차단 해제 후 재위반 | 누적 차단 (1→1분, 2→5분, 3→30분, 4+→영구) |

## PathScannerDetector

| 조건 | Action |
|------|--------|
| 알려진 취약점 열거 경로 접근 | Block |

탐지 경로 예시: `.env`, `.git/`, `wp-admin`, `phpmyadmin`, `xmlrpc.php`, `shell.php`, `/etc/passwd`, `actuator/`, `telescope/`, `config.php`, `backup/` 등 28개.

## Ja3FingerprintDetector

X-JA3-Fingerprint 헤더 기반 TLS 지문 탐지. nginx-module-ja3 또는 OpenResty 필요.
현재 HTTP 전용 환경에서는 헤더 미전달로 항상 Pass (하위 호환).

| 조건 | Action |
|------|--------|
| `X-JA3-Fingerprint` 헤더 없음 | Pass |
| 알려진 봇 JA3 (`c398c55...` python-requests, `764b89...` curl 등) | Block |
| 브라우저 UA + 화이트리스트 JA3 매칭 | Pass |
| 브라우저 UA + 미등록 JA3 | Challenge (Chrome 110+/Firefox 114+ 랜덤화로 Block 시 오탐) |
| 알 수 없는 UA + 미등록 JA3 | Challenge |

봇 블랙리스트 (TrisulNSM·ja3er.com 출처):
- `c398c55518355639c5a866c15784f969` — python-requests 2.4.3
- `a48c0d5f95b1ef98f560f324fd275da1` — Python urllib3
- `764b8952983230b0ac23dbd3741d2bb0` — curl 7.22 Linux
- `9f198208a855994e1b8ec82c892b7d37` — curl 7.43 macOS
- `de4c3d0f370ff1dc78eccd89307bbb28` — curl 7.6x+ OpenSSL

## UserAgentDetector

| 조건 | Action |
|------|--------|
| UA 헤더 없음 | Block |
| 알려진 봇/스캐너 UA (`python-requests`, `curl`, `wget`, `scrapy`, `go-http-client`, `bot`, `crawler`, `spider`, `selenium`, `nikto`, `sqlmap` 등) | Block |
| 정상 브라우저 UA (`Mozilla/5.0 ...` Chrome/Firefox/Safari/Edge) | Pass |
| 그 외 (미등록 UA) | Challenge |

## HeaderFingerprintDetector

점수 누적 방식:

| 조건 | 점수 |
|------|------|
| `Accept: */*` | +30 |
| `Accept-Language` 헤더 없음 | +30 |
| `Accept-Encoding` 헤더 없음 | +20 |
| `Connection: close` | +20 |

| 합산 점수 | Action |
|-----------|--------|
| 0~30 | Pass |
| 31~60 | Challenge |
| 61+ | Block |

## CredentialStuffingDetector

로그인 엔드포인트(`/login`, `/signin`, `/auth`, `/api/login` 등 POST)에만 적용.

| 조건 | Action |
|------|--------|
| 동일 IP 60초 내 로그인 시도 ≥ 5회 | Block (5분) |
| 동일 username 3개+ IP에서 시도 | Block |

## JsChallengeDetector

| 조건 | Action |
|------|--------|
| 챌린지 쿠키 없음 | Challenge (JS 폼 자동 submit) |
| 쿠키 서명 불일치 또는 IP 불일치 | Block |
| 쿠키 만료 (1시간) | Challenge |
| 쿠키 유효 | Pass |

검증 엔드포인트: `/__mini-protection/js-challenge/verify`

## CaptchaDetector

| 조건 | Action |
|------|--------|
| JS Challenge 미통과 | Pass (Captcha 생략) |
| `CAPTCHA_SITE_KEY` 미설정 | Pass (우회) |
| CAPTCHA 쿠키 없음/만료 | Captcha |
| 쿠키 서명 불일치 | Block |
| 쿠키 유효 | Pass |

검증 엔드포인트: `/__mini-protection/captcha/verify`
