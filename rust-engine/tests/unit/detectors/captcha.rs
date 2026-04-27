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
