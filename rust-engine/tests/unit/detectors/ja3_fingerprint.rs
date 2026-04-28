use super::*;
use crate::pipeline::detector::Action;
use std::net::IpAddr;

fn detector() -> Ja3FingerprintDetector {
    Ja3FingerprintDetector::new()
}

fn packet(ja3: Option<&str>, ua: &str) -> Packet {
    let mut p = Packet::new(
        "1.2.3.4".parse::<IpAddr>().unwrap(),
        "10.0.0.1".parse::<IpAddr>().unwrap(),
    );
    p.ja3_fingerprint = ja3.map(|s| s.to_string());
    p.user_agent = ua.to_string();
    p
}

const CHROME_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

#[test]
fn no_ja3_header_passes() {
    let r = detector().detect(&packet(None, ""));
    assert!(r.is_pass(), "JA3 헤더 없으면 무조건 Pass");
}

#[test]
fn blacklisted_ja3_blocks() {
    // python-requests JA3 → Block
    let r = detector().detect(&packet(
        Some("c398c55518355639c5a866c15784f969"),
        "python-requests/2.31.0",
    ));
    assert!(r.is_block());
    assert!(r.reason.contains("Blacklisted JA3 fingerprint"));
}

#[test]
fn blacklisted_ja3_with_browser_ua_still_blocks() {
    // curl JA3 + 브라우저 UA 위장 → 블랙리스트가 먼저 체크되어 Block
    let r = detector().detect(&packet(
        Some("764b8952983230b0ac23dbd3741d2bb0"),
        CHROME_UA,
    ));
    assert!(r.is_block());
    assert!(r.reason.contains("curl 7.22 Linux"));
}

#[test]
fn known_browser_ja3_with_browser_ua_passes() {
    // Chrome UA + 화이트리스트 JA3 → Pass
    let r = detector().detect(&packet(
        Some("c11ab92a9db8107e2a0b0486f35b80b9"),
        CHROME_UA,
    ));
    assert!(r.is_pass());
}

#[test]
fn browser_ua_with_unknown_ja3_challenges() {
    // Chrome UA지만 JA3가 화이트리스트 외 → Challenge
    // (Chrome 110+ 랜덤화로 인해 Block 대신 Challenge 사용)
    let r = detector().detect(&packet(
        Some("aaaabbbbccccdddd1111222233334444"),
        CHROME_UA,
    ));
    assert_eq!(r.action, Action::Challenge);
    assert!(r.reason.contains("UA/JA3 mismatch"));
}

#[test]
fn unknown_ua_with_unknown_ja3_challenges() {
    let r = detector().detect(&packet(
        Some("aaaabbbbccccdddd1111222233334444"),
        "MyCustomClient/1.0",
    ));
    assert_eq!(r.action, Action::Challenge);
    assert!(r.reason.contains("Unknown UA and JA3"));
}
