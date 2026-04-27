use super::*;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn make_packet(src: &str) -> Packet {
    Packet::new(ip(src), ip("127.0.0.1"))
}

#[test]
fn passes_under_threshold() {
    let limiter = IpRateLimiter::new();
    let p = make_packet("1.2.3.4");
    for _ in 0..THRESHOLD {
        assert!(limiter.detect(&p).is_pass());
    }
}

#[test]
fn blocks_on_threshold_exceeded() {
    let limiter = IpRateLimiter::new();
    let p = make_packet("1.2.3.5");
    for _ in 0..THRESHOLD {
        limiter.detect(&p);
    }
    let result = limiter.detect(&p); // 31번째
    assert!(result.is_block());
    assert!(result.reason.contains("violations: 1"));
}

#[test]
fn permanent_block_after_four_violations() {
    let limiter = IpRateLimiter::new();
    let p = make_packet("1.2.3.6");

    {
        let mut entry = limiter
            .entries
            .entry(ip("1.2.3.6"))
            .or_insert_with(|| IpEntry::new(ip("1.2.3.6"), now_secs()));
        entry.violation_cnt = 4;
        entry.blocked = true;
        entry.blocked_until = u64::MAX;
    }

    let result = limiter.detect(&p);
    assert!(result.is_block());
    assert_eq!(result.reason, "IP permanently blocked");
}

#[test]
fn different_ips_are_independent() {
    let limiter = IpRateLimiter::new();
    let p_a = make_packet("10.0.0.1");
    let p_b = make_packet("10.0.0.2");

    for _ in 0..=THRESHOLD {
        limiter.detect(&p_a);
    }
    assert!(limiter.detect(&p_b).is_pass());
}
