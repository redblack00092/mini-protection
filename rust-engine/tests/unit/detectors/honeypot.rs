use super::*;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn make_packet(src: &str) -> Packet {
    Packet::new(ip(src), ip("127.0.0.1"))
}

#[test]
fn passes_unknown_ip() {
    let store: HoneypotStore = Arc::new(DashMap::new());
    let d = HoneypotDetector::new(store);
    assert!(d.detect(&make_packet("1.2.3.4")).is_pass());
}

#[test]
fn blocks_caught_ip() {
    let store: HoneypotStore = Arc::new(DashMap::new());
    store.insert(ip("1.2.3.4"), ());
    let d = HoneypotDetector::new(Arc::clone(&store));
    let result = d.detect(&make_packet("1.2.3.4"));
    assert!(result.is_block());
    assert_eq!(result.reason, "Honeypot trap triggered");
}

#[test]
fn different_ip_not_blocked() {
    let store: HoneypotStore = Arc::new(DashMap::new());
    store.insert(ip("1.2.3.4"), ());
    let d = HoneypotDetector::new(Arc::clone(&store));
    assert!(d.detect(&make_packet("5.6.7.8")).is_pass());
}

#[test]
fn store_shared_across_detectors() {
    let store: HoneypotStore = Arc::new(DashMap::new());
    let d = HoneypotDetector::new(Arc::clone(&store));

    store.insert(ip("9.9.9.9"), ());

    let result = d.detect(&make_packet("9.9.9.9"));
    assert!(result.is_block());
}
