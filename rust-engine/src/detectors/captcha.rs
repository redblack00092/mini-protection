use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};
use std::time::{SystemTime, UNIX_EPOCH};

// ── 상수 ──────────────────────────────────────────────────────────────────

/// CAPTCHA 통과 쿠키 이름
const CAPTCHA_COOKIE: &str = "mini_protection_captcha_pass";
/// CAPTCHA 통과 쿠키 TTL (초) — 1시간
const CAPTCHA_TTL_SECS: u64 = 3600;
/// HMAC 서명용 시크릿
const DEFAULT_SECRET: &[u8] = b"mini-protection-captcha-secret-change-in-production";
/// reCAPTCHA 토큰 파라미터 이름 (커스텀)
const RECAPTCHA_PARAM: &str = "mini_protection_captcha_token";

// ── 헬퍼 ──────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sign(payload: &str, secret: &[u8]) -> String {
    let payload_bytes = payload.as_bytes();
    let sig: Vec<u8> = payload_bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ secret[i % secret.len()])
        .collect();
    sig.iter().map(|b| format!("{b:02x}")).collect()
}

fn build_cookie_value(ip: &str, secret: &[u8]) -> String {
    let now = now_secs();
    let payload = format!("{now}:{ip}");
    let sig = sign(&payload, secret);
    format!("{payload}:{sig}")
}

fn verify_cookie_value(value: &str, ip: &str, secret: &[u8]) -> Result<bool, &'static str> {
    let parts: Vec<&str> = value.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err("invalid format");
    }
    let (ts_str, cookie_ip, sig) = (parts[0], parts[1], parts[2]);

    if cookie_ip != ip {
        return Err("ip mismatch");
    }

    let payload = format!("{ts_str}:{cookie_ip}");
    let expected_sig = sign(&payload, secret);
    if sig != expected_sig {
        return Err("signature invalid");
    }

    let ts: u64 = ts_str.parse().map_err(|_| "invalid timestamp")?;
    let now = now_secs();

    if now.saturating_sub(ts) > CAPTCHA_TTL_SECS {
        return Ok(false);
    }

    Ok(true)
}

/// POST body에서 CAPTCHA token 추출
fn extract_captcha_token(body: &[u8]) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;
    body_str.split('&').find_map(|pair| {
        let mut iter = pair.splitn(2, '=');
        let key = iter.next()?.trim();
        if key == RECAPTCHA_PARAM {
            let val = iter.next()?.trim().to_string();
            if val.len() > 20 {
                // 최소 길이 검증 (reCAPTCHA token은 수백자)
                return Some(val);
            }
        }
        None
    })
}

// ── CaptchaDetector ───────────────────────────────────────────────────────

/// CAPTCHA 기반 봇 탐지:
///
/// WAF 자체는 외부 API 호출 없이 폐쇄망에서 동작한다.
/// - reCAPTCHA JS를 포함한 HTML을 WAF가 직접 생성하여 클라이언트에게 응답
/// - 클라이언트 브라우저가 Google reCAPTCHA JS 로드 및 처리
/// - 커스텀 파라미터로 token 수신 → token 존재 여부만 확인
/// - 통과 시 자체 서명 쿠키 발급
pub struct CaptchaDetector {
    secret: Vec<u8>,
}

impl CaptchaDetector {
    pub fn new() -> Self {
        Self {
            secret: DEFAULT_SECRET.to_vec(),
        }
    }

    pub fn with_secret(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    /// CAPTCHA 통과 시 발급할 쿠키 값 생성
    pub fn issue_cookie(&self, ip: &str) -> String {
        build_cookie_value(ip, &self.secret)
    }

    /// CAPTCHA token 검증 (token 존재 여부 + 최소 길이)
    /// WAF 서버 자체는 Google API 호출 없이 폐쇄망에서 동작
    fn verify_token(token: &str) -> bool {
        !token.is_empty() && token.len() > 20
    }
}

impl Detector for CaptchaDetector {
    fn name(&self) -> &str {
        "captcha"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        // 이미 통과한 경우 즉시 Pass
        if packet.captcha_passed {
            return DetectionResult::pass();
        }

        let ip = packet.src_ip.to_string();

        // CAPTCHA 쿠키 확인 — 위변조/만료는 JS 챌린지 상태와 무관하게 처리
        if let Some(cookie_value) = packet.cookie.get(CAPTCHA_COOKIE) {
            return match verify_cookie_value(cookie_value, &ip, &self.secret) {
                Ok(true) => DetectionResult::pass(),
                Ok(false) => DetectionResult::captcha("CAPTCHA required: cookie expired", 0.9),
                Err(reason) => DetectionResult::block(
                    format!("CAPTCHA cookie tampered: {reason}"),
                    1.0,
                ),
            };
        }

        // JS 챌린지를 아직 통과하지 않았으면 CAPTCHA 요구하지 않음
        if !packet.js_challenge_passed {
            return DetectionResult::pass();
        }

        // POST 요청에서 CAPTCHA token 확인 (CAPTCHA 풀고 돌아온 요청)
        if packet.method.eq_ignore_ascii_case("POST") {
            if let Some(token) = extract_captcha_token(&packet.body) {
                if Self::verify_token(&token) {
                    return DetectionResult::pass();
                } else {
                    return DetectionResult::captcha("CAPTCHA token invalid", 0.9);
                }
            }
        }

        // JS 챌린지 통과 후 CAPTCHA 쿠키/토큰 없음 → CAPTCHA 발급
        DetectionResult::captcha(
            "CAPTCHA required: no valid token or cookie",
            0.9,
        )
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

    fn detector() -> CaptchaDetector {
        CaptchaDetector::with_secret(TEST_SECRET.to_vec())
    }

    fn base_packet() -> Packet {
        Packet::new(
            TEST_IP.parse::<IpAddr>().unwrap(),
            "10.0.0.1".parse::<IpAddr>().unwrap(),
        )
    }

    fn packet_with_cookie(value: &str) -> Packet {
        let mut p = base_packet();
        p.cookie.insert(CAPTCHA_COOKIE.to_string(), value.to_string());
        p
    }

    fn packet_with_token(token: &str) -> Packet {
        let mut p = base_packet();
        p.js_challenge_passed = true;
        p.method = "POST".to_string();
        p.body = format!("{RECAPTCHA_PARAM}={token}").into_bytes();
        p
    }

    fn packet_js_passed() -> Packet {
        let mut p = base_packet();
        p.js_challenge_passed = true;
        p
    }

    #[test]
    fn passes_when_js_challenge_not_passed() {
        // JS 챌린지 미통과 → CAPTCHA 요구하지 않고 Pass
        let d = detector();
        let result = d.detect(&base_packet());
        assert!(result.is_pass());
    }

    #[test]
    fn captcha_required_when_no_cookie_no_token() {
        let d = detector();
        let result = d.detect(&packet_js_passed());
        assert_eq!(result.action, Action::Captcha);
        assert!(result.reason.contains("no valid token or cookie"));
    }

    #[test]
    fn passes_when_already_passed() {
        let d = detector();
        let mut p = base_packet();
        p.captcha_passed = true;
        assert!(d.detect(&p).is_pass());
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
        let result = d.detect(&packet_with_cookie("bad:data:sig"));
        assert!(result.is_block());
        assert!(result.reason.contains("tampered"));
    }

    #[test]
    fn blocks_wrong_ip_cookie() {
        let d = detector();
        let cookie = build_cookie_value("9.9.9.9", TEST_SECRET);
        let result = d.detect(&packet_with_cookie(&cookie));
        assert!(result.is_block());
    }

    #[test]
    fn captcha_required_when_cookie_expired() {
        let d = detector();
        let old_ts = now_secs() - CAPTCHA_TTL_SECS - 1;
        let payload = format!("{old_ts}:{TEST_IP}");
        let sig = sign(&payload, TEST_SECRET);
        let cookie = format!("{payload}:{sig}");
        let result = d.detect(&packet_with_cookie(&cookie));
        assert_eq!(result.action, Action::Captcha);
        assert!(result.reason.contains("expired"));
    }

    #[test]
    fn passes_with_valid_token() {
        let d = detector();
        let token = "a".repeat(100);
        let result = d.detect(&packet_with_token(&token));
        assert!(result.is_pass());
    }

    #[test]
    fn captcha_required_with_short_token() {
        let d = detector();
        let result = d.detect(&packet_with_token("short"));
        assert_eq!(result.action, Action::Captcha);
    }

    #[test]
    fn issue_cookie_produces_valid_cookie() {
        let d = detector();
        let cookie = d.issue_cookie(TEST_IP);
        let result = d.detect(&packet_with_cookie(&cookie));
        assert!(result.is_pass());
    }
}
