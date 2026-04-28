use super::*;
use crate::pipeline::detector::Action;
use std::collections::HashSet;
use std::net::IpAddr;

const BOT_JA3: &str = "c398c55518355639c5a866c15784f969"; // python-requests
const CURL_JA3: &str = "764b8952983230b0ac23dbd3741d2bb0"; // curl 7.22
const BROWSER_JA3: &str = "c11ab92a9db8107e2a0b0486f35b80b9"; // Chrome 124 Windows
const UNKNOWN_JA3: &str = "aaaabbbbccccdddd1111222233334444";

const CHROME_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

fn detector() -> Ja3FingerprintDetector {
    let blacklist: HashSet<String> = [BOT_JA3, CURL_JA3]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let whitelist: HashSet<String> = [BROWSER_JA3].iter().map(|s| s.to_string()).collect();
    Ja3FingerprintDetector::with_sets(blacklist, whitelist)
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

#[test]
fn no_ja3_header_passes() {
    let r = detector().detect(&packet(None, ""));
    assert!(r.is_pass());
}

#[test]
fn empty_ja3_passes() {
    let r = detector().detect(&packet(Some(""), CHROME_UA));
    assert!(r.is_pass());
}

#[test]
fn blacklisted_ja3_blocks() {
    let r = detector().detect(&packet(Some(BOT_JA3), "python-requests/2.31.0"));
    assert!(r.is_block());
    assert!(r.reason.contains("Blacklisted JA3"));
}

#[test]
fn blacklisted_ja3_with_browser_ua_still_blocks() {
    // 블랙리스트가 UA보다 먼저 체크되므로 브라우저 UA여도 Block
    let r = detector().detect(&packet(Some(CURL_JA3), CHROME_UA));
    assert!(r.is_block());
    assert!(r.reason.contains("Blacklisted JA3"));
}

#[test]
fn whitelist_ja3_with_browser_ua_passes() {
    // 화이트리스트 + 브라우저 UA → Pass
    let r = detector().detect(&packet(Some(BROWSER_JA3), CHROME_UA));
    assert!(r.is_pass());
}

#[test]
fn whitelist_ja3_with_non_browser_ua_challenges() {
    // 화이트리스트 JA3지만 UA가 봇 → Challenge (TLS 스푸핑 의심)
    let r = detector().detect(&packet(Some(BROWSER_JA3), "python-requests/2.31.0"));
    assert_eq!(r.action, Action::Challenge);
    assert!(r.reason.contains("non-browser UA"));
}

#[test]
fn browser_ua_with_unknown_ja3_challenges() {
    // 브라우저 UA지만 JA3 미등록 → Challenge (Chrome 110+ 랜덤화 가능성)
    let r = detector().detect(&packet(Some(UNKNOWN_JA3), CHROME_UA));
    assert_eq!(r.action, Action::Challenge);
    assert!(r.reason.contains("not in whitelist"));
}

#[test]
fn unknown_ua_with_unknown_ja3_challenges() {
    let r = detector().detect(&packet(Some(UNKNOWN_JA3), "MyCustomClient/1.0"));
    assert_eq!(r.action, Action::Challenge);
    assert!(r.reason.contains("Unknown UA and JA3"));
}
