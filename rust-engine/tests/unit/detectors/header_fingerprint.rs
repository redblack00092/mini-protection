use super::*;
use crate::pipeline::detector::Action;
use std::net::IpAddr;

fn detector() -> HeaderFingerprintDetector {
    HeaderFingerprintDetector::new()
}

fn base_packet() -> Packet {
    Packet::new(
        "1.2.3.4".parse::<IpAddr>().unwrap(),
        "10.0.0.1".parse::<IpAddr>().unwrap(),
    )
}

fn normal_packet() -> Packet {
    let mut p = base_packet();
    p.headers.insert("accept".into(), "text/html,application/xhtml+xml,*/*".into());
    p.headers.insert("accept-language".into(), "ko-KR,ko;q=0.9,en-US;q=0.8".into());
    p.headers.insert("accept-encoding".into(), "gzip, deflate, br".into());
    p.headers.insert("connection".into(), "keep-alive".into());
    p
}

#[test]
fn passes_normal_browser() {
    assert!(detector().detect(&normal_packet()).is_pass());
}

#[test]
fn passes_score_30_exactly() {
    let mut p = normal_packet();
    p.headers.insert("accept".into(), "*/*".into());
    assert!(detector().detect(&p).is_pass());
}

#[test]
fn challenges_score_50() {
    let mut p = base_packet();
    p.headers.insert("accept".into(), "*/*".into());
    p.headers.insert("accept-language".into(), "en-US".into());
    let r = detector().detect(&p);
    assert_eq!(r.action, Action::Challenge);
    assert!(r.reason.contains("score: 50"));
    assert!((r.confidence - 0.5).abs() < f32::EPSILON);
}

#[test]
fn challenges_score_31() {
    let mut p = base_packet();
    p.headers.insert("accept".into(), "*/*".into());
    p.headers.insert("accept-language".into(), "en".into());
    p.headers.insert("accept-encoding".into(), "gzip".into());
    p.headers.insert("connection".into(), "close".into());
    let r = detector().detect(&p);
    assert_eq!(r.action, Action::Challenge);
}

#[test]
fn blocks_score_100() {
    let mut p = base_packet();
    p.headers.insert("accept".into(), "*/*".into());
    let r = detector().detect(&p);
    assert!(r.is_block());
    assert!(r.reason.contains("score: 80"));
}

#[test]
fn blocks_all_suspicious() {
    let mut p = base_packet();
    p.headers.insert("accept".into(), "*/*".into());
    p.headers.insert("connection".into(), "close".into());
    let r = detector().detect(&p);
    assert!(r.is_block());
    assert!(r.reason.contains("score: 100"));
}

#[test]
fn blocks_score_exactly_61() {
    let mut p = base_packet();
    p.headers.insert("accept".into(), "text/html".into());
    p.headers.insert("connection".into(), "close".into());
    let r = detector().detect(&p);
    assert!(r.is_block());
}

#[test]
fn connection_close_case_insensitive() {
    let mut p = normal_packet();
    p.headers.insert("connection".into(), "Close".into());
    let r = detector().detect(&p);
    assert!(r.is_pass());
}
