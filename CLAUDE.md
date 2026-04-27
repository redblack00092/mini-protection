# WAF Bot Detection Engine - 개발 원칙

## 프로젝트 배경
- 10년간 C++ WAF 개발 경험 기반으로 설계
- Rust로 Bot Detection Reverse Proxy 구현
- 단일 프로세스, 멀티스레드 환경

## 아키텍처
- Nginx → Rust 엔진(8080) → Kafka → Backend
- Packet 구조체를 파이프라인에 참조로 전달
- Detector trait 기반 확장 가능한 탐지 모듈 구조

## 성능 원칙 (모든 코드에 반드시 적용)
- 함수 인자는 소유권 이전 대신 참조(&) 사용
- String 반환보다 &'static str 또는 Cow<'_, str> 우선
- 불필요한 clone() 금지
- heap 할당 최소화 (스택 활용 우선)
- DashMap entry API 활용으로 lock 전환 최소화
- Arc<T>로 공유, 복사 없이 참조 카운팅
- detect() 함수는 &Packet 참조만 받고 소유하지 않음
- zero-copy 원칙: Packet 데이터는 복사하지 않음

## 코딩 컨벤션
- 에러 처리: anyhow::Result 사용
- 로깅: tracing 매크로 사용
- 비동기: tokio 런타임
- 모든 pub 함수에 doc comment 작성

## 탐지 파이프라인 순서
1. IpRateLimiter
2. UserAgentDetector
3. HeaderFingerprint
4. CredentialStuffing
5. JsChallenge
6. Captcha

## 탐지 모듈 추가 방법
1. detectors/ 에 새 파일 생성
2. Detector trait 구현
3. pipeline/mod.rs에 등록
→ 이게 전부

## IpRateLimiter 정책
- blocked_until = 0: 차단 없음 (초기값)
- blocked_until = u64::MAX: 영구차단
- 그 외: unix timestamp (차단 해제 시간)

## Kafka 이벤트
- 모든 탐지 결과를 Kafka로 스트리밍
- Block/Challenge/Captcha 액션만 전송 (Pass는 제외)
