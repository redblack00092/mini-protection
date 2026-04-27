use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};
use std::time::{SystemTime, UNIX_EPOCH};

// ── 상수 ──────────────────────────────────────────────────────────────────

/// JS Challenge 쿠키 이름
const CHALLENGE_COOKIE: &str = "mini_protection_js_challenge";
/// JS Challenge 쿠키 TTL (초) — 1시간
const CHALLENGE_TTL_SECS: u64 = 3600;
/// HMAC 서명용 시크릿 (실제 운영 시 환경변수에서 로드)
const DEFAULT_SECRET: &[u8] = b"mini-protection-js-challenge-secret-change-in-production";

// ── 헬퍼 ──────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 간단한 HMAC-SHA256 대신 XOR 기반 서명 (외부 의존성 최소화)
/// 실제 운영에서는 hmac + sha2 크레이트 사용 권장
fn sign(payload: &str, secret: &[u8]) -> String {
    let payload_bytes = payload.as_bytes();
    let sig: Vec<u8> = payload_bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ secret[i % secret.len()])
        .collect();
    // hex 인코딩
    sig.iter().map(|b| format!("{b:02x}")).collect()
}

/// 쿠키 값 생성: base64(timestamp:ip):signature
fn build_cookie_value(ip: &str, secret: &[u8]) -> String {
    let now = now_secs();
    let payload = format!("{now}:{ip}");
    let sig = sign(&payload, secret);
    format!("{payload}:{sig}")
}

/// 쿠키 값 검증
/// 반환값: Ok(true) = 유효, Ok(false) = 만료, Err = 위변조
fn verify_cookie_value(value: &str, ip: &str, secret: &[u8]) -> Result<bool, &'static str> {
    // format: timestamp:ip:signature
    let parts: Vec<&str> = value.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err("invalid format");
    }
    let (ts_str, cookie_ip, sig) = (parts[0], parts[1], parts[2]);

    // IP 일치 확인
    if cookie_ip != ip {
        return Err("ip mismatch");
    }

    // 서명 검증
    let payload = format!("{ts_str}:{cookie_ip}");
    let expected_sig = sign(&payload, secret);
    if sig != expected_sig {
        return Err("signature invalid");
    }

    // 타임스탬프 파싱
    let ts: u64 = ts_str.parse().map_err(|_| "invalid timestamp")?;
    let now = now_secs();

    // 만료 확인
    if now.saturating_sub(ts) > CHALLENGE_TTL_SECS {
        return Ok(false); // 만료
    }

    Ok(true)
}

// ── JsChallengeDetector ───────────────────────────────────────────────────

/// JS Challenge 기반 봇 탐지:
/// 1. JS Challenge 쿠키가 없으면 → Challenge (JS 실행 불가 봇 차단)
/// 2. 쿠키가 위변조됐으면 → Block
/// 3. 쿠키가 만료됐으면 → Challenge (재검증)
/// 4. 쿠키가 유효하면 → Pass
pub struct JsChallengeDetector {
    secret: Vec<u8>,
}

impl JsChallengeDetector {
    pub fn new() -> Self {
        Self {
            secret: DEFAULT_SECRET.to_vec(),
        }
    }

    pub fn with_secret(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    /// JS Challenge 통과 시 발급할 쿠키 값 생성 (외부에서 호출)
    pub fn issue_cookie(&self, ip: &str) -> String {
        build_cookie_value(ip, &self.secret)
    }

    /// 쿠키 값이 해당 IP에 대해 유효한지 확인한다 (파이프라인 전처리용).
    pub fn is_cookie_valid(&self, value: &str, ip: &str) -> bool {
        verify_cookie_value(value, ip, &self.secret) == Ok(true)
    }
}

impl Detector for JsChallengeDetector {
    fn name(&self) -> &str {
        "js_challenge"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        // 이미 통과한 경우 즉시 Pass
        if packet.js_challenge_passed {
            return DetectionResult::pass();
        }

        // 쿠키 확인
        let Some(cookie_value) = packet.cookie.get(CHALLENGE_COOKIE) else {
            // 쿠키 없음 → JS Challenge 발급
            return DetectionResult::challenge(
                "JS Challenge required: no challenge cookie",
                0.7,
            );
        };

        let ip = packet.src_ip.to_string();

        match verify_cookie_value(cookie_value, &ip, &self.secret) {
            Ok(true) => DetectionResult::pass(),
            Ok(false) => DetectionResult::challenge(
                "JS Challenge required: cookie expired",
                0.7,
            ),
            Err(reason) => DetectionResult::block(
                format!("JS Challenge cookie tampered: {reason}"),
                1.0,
            ),
        }
    }
}

// ── 단위 테스트 ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::detector::Action;
    use std::net::IpAddr;

    const TEST_SECRET: &[u8] = b"test-secret";
    const TEST_IP: &str = "1.2.3.4";

    fn detector() -> JsChallengeDetector {
        JsChallengeDetector::with_secret(TEST_SECRET.to_vec())
    }

    fn packet_without_cookie() -> Packet {
        Packet::new(
            TEST_IP.parse::<IpAddr>().unwrap(),
            "10.0.0.1".parse::<IpAddr>().unwrap(),
        )
    }

    fn packet_with_cookie(value: &str) -> Packet {
        let mut p = packet_without_cookie();
        p.cookie.insert(CHALLENGE_COOKIE.to_string(), value.to_string());
        p
    }

    fn packet_already_passed() -> Packet {
        let mut p = packet_without_cookie();
        p.js_challenge_passed = true;
        p
    }

    #[test]
    fn challenges_when_no_cookie() {
        let d = detector();
        let result = d.detect(&packet_without_cookie());
        assert_eq!(result.action, Action::Challenge);
        assert!(result.reason.contains("no challenge cookie"));
    }

    #[test]
    fn passes_when_already_passed() {
        let d = detector();
        let result = d.detect(&packet_already_passed());
        assert!(result.is_pass());
    }

    #[test]
    fn passes_with_valid_cookie() {
        let d = detector();
        let cookie = build_cookie_value(TEST_IP, TEST_SECRET);
        let result = d.detect(&packet_with_cookie(&cookie));
        assert!(result.is_pass());
    }

    #[test]
    fn blocks_tampered_cookie() {
        let d = detector();
        let result = d.detect(&packet_with_cookie("tampered:value:badsig"));
        assert!(result.is_block());
        assert!(result.reason.contains("tampered"));
    }

    #[test]
    fn blocks_wrong_ip_cookie() {
        let d = detector();
        // 다른 IP로 발급된 쿠키
        let cookie = build_cookie_value("9.9.9.9", TEST_SECRET);
        let result = d.detect(&packet_with_cookie(&cookie));
        assert!(result.is_block());
        assert!(result.reason.contains("ip mismatch"));
    }

    #[test]
    fn challenges_expired_cookie() {
        let d = detector();
        // 만료된 타임스탬프로 쿠키 직접 생성
        let old_ts = now_secs() - CHALLENGE_TTL_SECS - 1;
        let payload = format!("{old_ts}:{TEST_IP}");
        let sig = sign(&payload, TEST_SECRET);
        let cookie = format!("{payload}:{sig}");
        let result = d.detect(&packet_with_cookie(&cookie));
        assert_eq!(result.action, Action::Challenge);
        assert!(result.reason.contains("expired"));
    }

    #[test]
    fn issue_cookie_produces_valid_cookie() {
        let d = detector();
        let cookie = d.issue_cookie(TEST_IP);
        let result = d.detect(&packet_with_cookie(&cookie));
        assert!(result.is_pass());
    }
}
