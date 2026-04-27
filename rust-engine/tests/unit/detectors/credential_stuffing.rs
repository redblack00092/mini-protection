use super::*;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn login_packet(src: &str, username: &str) -> Packet {
    let mut p = Packet::new(ip(src), ip("10.0.0.1"));
    p.method = "POST".to_string();
    p.uri = "/login".to_string();
    p.body = format!("username={username}&password=test123").into_bytes();
    p
}

fn non_login_packet(src: &str) -> Packet {
    let mut p = Packet::new(ip(src), ip("10.0.0.1"));
    p.method = "GET".to_string();
    p.uri = "/home".to_string();
    p
}

#[test]
fn passes_non_login_endpoint() {
    let d = CredentialStuffingDetector::new();
    let p = non_login_packet("1.2.3.4");
    assert!(d.detect(&p).is_pass());
}

#[test]
fn passes_under_ip_threshold() {
    let d = CredentialStuffingDetector::new();
    let p = login_packet("1.2.3.4", "user1");
    for _ in 0..IP_LOGIN_THRESHOLD {
        assert!(d.detect(&p).is_pass());
    }
}

#[test]
fn blocks_on_ip_threshold_exceeded() {
    let d = CredentialStuffingDetector::new();
    let p = login_packet("1.2.3.5", "user2");
    for _ in 0..IP_LOGIN_THRESHOLD {
        d.detect(&p);
    }
    let result = d.detect(&p);
    assert!(result.is_block());
    assert!(result.reason.contains("too many login attempts")
        || result.reason.contains("exceeded"));
}

#[test]
fn blocks_distributed_attack() {
    let d = CredentialStuffingDetector::new();
    for i in 0..=USERNAME_IP_THRESHOLD {
        let p = login_packet(&format!("1.2.3.{}", i + 10), "victim");
        let _ = d.detect(&p);
    }
    let p = login_packet("1.2.3.99", "victim");
    let result = d.detect(&p);
    assert!(result.is_block());
    assert!(result.reason.contains("distributed attack"));
}

#[test]
fn different_usernames_are_independent() {
    let d = CredentialStuffingDetector::new();
    for i in 0..=USERNAME_IP_THRESHOLD {
        let p = login_packet(&format!("2.2.2.{}", i), "user_a");
        d.detect(&p);
    }
    let p = login_packet("3.3.3.3", "user_b");
    assert!(d.detect(&p).is_pass());
}
