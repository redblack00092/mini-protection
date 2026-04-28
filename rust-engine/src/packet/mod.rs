use std::collections::HashMap;
use std::net::IpAddr;

/// HTTP 요청 패킷 — WAF 파이프라인 전체를 관통하는 핵심 자료구조.
/// 각 detector는 이 구조체를 읽기 전용으로 참조하고,
/// 상태 갱신(js_challenge_passed 등)은 파이프라인 조율자가 담당한다.
#[derive(Debug, Clone)]
pub struct Packet {
    // ── 네트워크 계층 ──────────────────────────────────────────────
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,

    // ── 타임스탬프 (Unix epoch ms) ─────────────────────────────────
    pub timestamp: u64,

    // ── HTTP 요청 라인 ─────────────────────────────────────────────
    pub method: String,
    pub uri: String,
    pub http_version: String,

    // ── 헤더 ──────────────────────────────────────────────────────
    /// 헤더 이름은 소문자 정규화 (e.g. "content-type")
    pub headers: HashMap<String, String>,
    pub user_agent: String,
    pub host: String,
    pub referer: String,

    // ── 바디 ──────────────────────────────────────────────────────
    pub body: Vec<u8>,

    // ── 쿠키 ──────────────────────────────────────────────────────
    pub cookie: HashMap<String, String>,

    // ── 챌린지 통과 여부 ───────────────────────────────────────────
    pub js_challenge_passed: bool,
    pub captcha_passed: bool,

    // ── 위반 누적 카운트 ───────────────────────────────────────────
    pub violation_count: u32,

    // ── TLS 지문 ───────────────────────────────────────────────────
    /// nginx-module-ja3 또는 OpenResty가 계산한 JA3 해시 (X-JA3-Fingerprint 헤더)
    pub ja3_fingerprint: Option<String>,
}

impl Packet {
    /// axum/hyper에서 추출한 정보를 받아 Packet을 생성하는 팩토리.
    /// 실제 파싱 로직은 구현 단계에서 채운다.
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr) -> Self {
        Self {
            src_ip,
            dst_ip,
            timestamp: 0,
            method: String::new(),
            uri: String::new(),
            http_version: String::new(),
            headers: HashMap::new(),
            user_agent: String::new(),
            host: String::new(),
            referer: String::new(),
            body: Vec::new(),
            cookie: HashMap::new(),
            js_challenge_passed: false,
            captcha_passed: false,
            violation_count: 0,
            ja3_fingerprint: None,
        }
    }

    /// Cookie 헤더 문자열을 파싱하여 cookie 맵을 채운다.
    /// e.g. "sessionid=abc; theme=dark"
    pub fn parse_cookies(cookie_header: &str) -> HashMap<String, String> {
        cookie_header
            .split(';')
            .filter_map(|pair| {
                let mut iter = pair.splitn(2, '=');
                let key = iter.next()?.trim().to_string();
                let val = iter.next().unwrap_or("").trim().to_string();
                Some((key, val))
            })
            .collect()
    }
}
