# Detection Rules

## IpRateLimiter

| 조건 | Action |
|------|--------|
| window 내 요청 수 > block_threshold | Block |
| window 내 요청 수 > challenge_threshold | Challenge |

## UserAgentDetector

| 조건 | Action |
|------|--------|
| UA 헤더 없음 | Challenge |
| 알려진 봇/스캐너 UA (regex) | Block |
| 비정상 버전 패턴 | Challenge |

## HeaderFingerprintDetector

| 조건 | Action |
|------|--------|
| 알려진 봇 지문 DB 일치 | Block |
| 의심스러운 지문 | Challenge |

## CredentialStuffingDetector

| 조건 | Action |
|------|--------|
| 동일 IP에서 window 내 로그인 시도 > N | Block |
| 동일 username에서 분산 시도 탐지 | Captcha |

## JsChallengeDetector

| 조건 | Action |
|------|--------|
| 챌린지 토큰 없음 | Challenge |
| 토큰 만료 또는 서명 불일치 | Challenge |
| 토큰 유효 | Pass |

## CaptchaDetector

| 조건 | Action |
|------|--------|
| CAPTCHA 토큰 없음 | Captcha |
| 토큰 검증 실패 | Captcha |
| 토큰 유효 | Pass |
