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
    let cookie = build_cookie_value("9.9.9.9", TEST_SECRET);
    let result = d.detect(&packet_with_cookie(&cookie));
    assert!(result.is_block());
    assert!(result.reason.contains("ip mismatch"));
}

#[test]
fn challenges_expired_cookie() {
    let d = detector();
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
