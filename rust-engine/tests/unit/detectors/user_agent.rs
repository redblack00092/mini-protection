use super::*;
use crate::pipeline::detector::Action;
use std::net::IpAddr;

fn detector() -> UserAgentDetector {
    UserAgentDetector::new()
}

fn packet_with_ua(ua: &str) -> Packet {
    let mut p = Packet::new(
        "1.2.3.4".parse::<IpAddr>().unwrap(),
        "10.0.0.1".parse::<IpAddr>().unwrap(),
    );
    p.user_agent = ua.to_string();
    p
}

#[test]
fn blocks_empty_ua() {
    let r = detector().detect(&packet_with_ua(""));
    assert!(r.is_block());
    assert_eq!(r.reason, "Empty User-Agent");
}

#[test]
fn blocks_python_requests() {
    let r = detector().detect(&packet_with_ua("python-requests/2.31.0"));
    assert!(r.is_block());
    assert!(r.reason.contains("Blacklisted User-Agent"));
}

#[test]
fn blocks_curl() {
    let r = detector().detect(&packet_with_ua("curl/7.88.1"));
    assert!(r.is_block());
}

#[test]
fn blocks_selenium() {
    let r = detector().detect(&packet_with_ua(
        "Mozilla/5.0 (Windows NT 10.0) selenium/4.0",
    ));
    assert!(r.is_block());
}

#[test]
fn blocks_sqlmap() {
    let r = detector().detect(&packet_with_ua("sqlmap/1.7"));
    assert!(r.is_block());
}

#[test]
fn passes_chrome() {
    let r = detector().detect(&packet_with_ua(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ));
    assert!(r.is_pass());
}

#[test]
fn passes_firefox() {
    let r = detector().detect(&packet_with_ua(
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ));
    assert!(r.is_pass());
}

#[test]
fn passes_edge() {
    let r = detector().detect(&packet_with_ua(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    ));
    assert!(r.is_pass());
}

#[test]
fn challenges_unknown_ua() {
    let r = detector().detect(&packet_with_ua("MyCustomClient/1.0"));
    assert_eq!(r.action, Action::Challenge);
    assert!(r.reason.contains("Unknown User-Agent"));
}
