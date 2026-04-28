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

OpenResty `ssl_client_hello_by_lua_block`에서 TLS ClientHello를 파싱해 JA3 해시를 계산하고
`X-JA3-Fingerprint` 헤더로 rust-engine에 전달. 현재 활성화됨.

**블랙리스트/화이트리스트는 파일로 관리** (`rust-engine/config/`):
- `ja3_blacklist.txt` — 45개 봇 해시 (재시작 없이 파일만 수정 후 컨테이너 재시작으로 반영)
- `ja3_whitelist.txt` — 29개 브라우저 해시

**탐지 로직:**

| 조건 | Action |
|------|--------|
| `X-JA3-Fingerprint` 헤더 없음 | Pass |
| 블랙리스트 JA3 | Block (UA 무관) |
| 화이트리스트 JA3 + 브라우저 UA | Pass |
| 화이트리스트 JA3 + 비브라우저 UA | Challenge (브라우저 TLS 스택 스푸핑 의심) |
| 미등록 JA3 + 브라우저 UA | Challenge (Chrome 110+/Firefox 114+ 랜덤화 가능성) |
| 미등록 JA3 + 비브라우저 UA | Challenge |

> 화이트리스트 단독 Pass를 쓰지 않는 이유: UA를 위조한 봇이 브라우저 TLS 스택을 흉내낼 경우 우회 가능.
> 블랙리스트 + 브라우저 UA 조합에서도 블랙리스트가 우선 적용되어 Block됨.

**블랙리스트 주요 항목** (전체 목록은 `ja3_blacklist.txt` 참고):

| 카테고리 | 해시 예시 |
|----------|-----------|
| Python requests / urllib3 | `c398c55...`, `443dc20...`, `a48c0d5...` |
| curl (버전별) | `764b895...`, `de4c3d0...`, `eaa1a9e...` 등 8개 |
| wget | `94b9404...`, `40adfd9...` |
| Node.js (Axios/node-fetch 공유) | `5d1b45c...`, `c4aac13...`, `4c319eb...` |
| Java / Apache HttpClient | `2db6873...` 등 8개 |
| Nikto | `f426296...` 등 3개 |
| Metasploit | `16f17c8...` 등 4개 |
| ZGrab / UMich Scanner | `9a1c3fe...` 등 3개 |
| BurpSuite | `c3ca411...`, `34f8cac...` |
| Rapid7 Nexpose / Nessus | `c22dea4...`, `24993ab...` |
| Shodan | `0b63812...` 등 4개 |

**공개 DB에 확정 해시 없는 도구:** Go net/http (Go 버전마다 변경), httpx, Scrapy, okhttp, Ruby net/http, PHP curl.
**Masscan:** TLS 직접 구현 안 함 → JA3 미해당. **sqlmap:** Python urllib3 해시 공유.

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
