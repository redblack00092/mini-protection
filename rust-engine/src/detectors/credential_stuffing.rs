use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

// ── 상수 ──────────────────────────────────────────────────────────────────

/// 로그인 시도 윈도우 (초)
const LOGIN_WINDOW_SECS: u64 = 60;
/// IP당 최대 로그인 시도 횟수
const IP_LOGIN_THRESHOLD: u32 = 5;
/// 동일 username으로 최대 시도 IP 수
const USERNAME_IP_THRESHOLD: u32 = 3;

/// 로그인 엔드포인트 URI 패턴
const LOGIN_URIS: &[&str] = &[
    "/login",
    "/signin",
    "/auth",
    "/api/login",
    "/api/signin",
    "/api/auth",
    "/user/login",
    "/account/login",
];

// ── 헬퍼 ──────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_login_endpoint(uri: &str) -> bool {
    let uri_lower = uri.to_lowercase();
    LOGIN_URIS.iter().any(|&ep| uri_lower.starts_with(ep))
}

// ── IP별 로그인 시도 카운터 ───────────────────────────────────────────────

struct IpLoginEntry {
    count: u32,
    window_start: u64,
    blocked: bool,
    blocked_until: u64,
}

impl IpLoginEntry {
    fn new(now: u64) -> Self {
        Self {
            count: 0,
            window_start: now,
            blocked: false,
            blocked_until: 0,
        }
    }
}

// ── Username별 시도 IP 추적 ───────────────────────────────────────────────

struct UsernameEntry {
    /// 시도한 IP 목록 (중복 제거)
    ips: Vec<IpAddr>,
    window_start: u64,
}

impl UsernameEntry {
    fn new(now: u64) -> Self {
        Self {
            ips: Vec::new(),
            window_start: now,
        }
    }
}

// ── CredentialStuffingDetector ────────────────────────────────────────────

/// Credential Stuffing 공격 탐지:
/// 1. 동일 IP에서 로그인 엔드포인트에 단시간 다수 시도
/// 2. 동일 username으로 여러 IP에서 분산 시도
pub struct CredentialStuffingDetector {
    /// IP → 로그인 시도 카운터
    ip_counters: DashMap<IpAddr, IpLoginEntry>,
    /// username → 시도 IP 목록
    username_ips: DashMap<String, UsernameEntry>,
}

impl CredentialStuffingDetector {
    pub fn new() -> Self {
        Self {
            ip_counters: DashMap::new(),
            username_ips: DashMap::new(),
        }
    }

    /// POST body에서 username 필드를 추출한다.
    /// form-urlencoded 형식: username=xxx&password=yyy
    fn extract_username(body: &[u8]) -> Option<String> {
        let body_str = std::str::from_utf8(body).ok()?;
        body_str
            .split('&')
            .find_map(|pair| {
                let mut iter = pair.splitn(2, '=');
                let key = iter.next()?.trim();
                if key.eq_ignore_ascii_case("username")
                    || key.eq_ignore_ascii_case("email")
                    || key.eq_ignore_ascii_case("id")
                {
                    let val = iter.next()?.trim().to_string();
                    if !val.is_empty() {
                        return Some(val);
                    }
                }
                None
            })
    }

    /// IP 기반 로그인 시도 횟수 체크
    fn check_ip_limit(&self, ip: IpAddr, now: u64) -> Option<DetectionResult> {
        let mut entry = self
            .ip_counters
            .entry(ip)
            .or_insert_with(|| IpLoginEntry::new(now));

        // 차단 상태 확인
        if entry.blocked {
            if entry.blocked_until == u64::MAX {
                return Some(DetectionResult::block(
                    "Credential stuffing: IP permanently blocked",
                    1.0,
                ));
            }
            if now < entry.blocked_until {
                return Some(DetectionResult::block(
                    "Credential stuffing: too many login attempts",
                    1.0,
                ));
            }
            // 차단 해제
            entry.blocked = false;
            entry.blocked_until = 0;
            entry.count = 0;
            entry.window_start = now;
        }

        // 윈도우 갱신
        if now.saturating_sub(entry.window_start) >= LOGIN_WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;

        // 임계값 초과
        if entry.count > IP_LOGIN_THRESHOLD {
            entry.blocked = true;
            entry.blocked_until = now + 300; // 5분 차단
            return Some(DetectionResult::block(
                format!(
                    "Credential stuffing: IP login attempts exceeded ({}/{})",
                    entry.count, IP_LOGIN_THRESHOLD
                ),
                1.0,
            ));
        }

        None
    }

    /// Username 기반 분산 공격 체크
    fn check_username_limit(
        &self,
        username: &str,
        ip: IpAddr,
        now: u64,
    ) -> Option<DetectionResult> {
        let mut entry = self
            .username_ips
            .entry(username.to_string())
            .or_insert_with(|| UsernameEntry::new(now));

        // 윈도우 갱신
        if now.saturating_sub(entry.window_start) >= LOGIN_WINDOW_SECS {
            entry.ips.clear();
            entry.window_start = now;
        }

        // 새 IP 추가 (중복 제거)
        if !entry.ips.contains(&ip) {
            entry.ips.push(ip);
        }

        // 임계값 초과 → 분산 공격
        if entry.ips.len() as u32 > USERNAME_IP_THRESHOLD {
            return Some(DetectionResult::block(
                format!(
                    "Credential stuffing: distributed attack on username '{}' from {} IPs",
                    username,
                    entry.ips.len()
                ),
                1.0,
            ));
        }

        None
    }
}

impl Detector for CredentialStuffingDetector {
    fn name(&self) -> &str {
        "credential_stuffing"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        // 로그인 엔드포인트가 아니면 즉시 통과
        if !is_login_endpoint(&packet.uri) {
            return DetectionResult::pass();
        }

        // POST 요청만 체크
        if !packet.method.eq_ignore_ascii_case("POST") {
            return DetectionResult::pass();
        }

        let now = now_secs();

        // 1. IP 기반 시도 횟수 체크
        if let Some(result) = self.check_ip_limit(packet.src_ip, now) {
            return result;
        }

        // 2. Username 기반 분산 공격 체크
        if let Some(username) = Self::extract_username(&packet.body) {
            if let Some(result) = self.check_username_limit(&username, packet.src_ip, now) {
                return result;
            }
        }

        DetectionResult::pass()
    }
}

// ── 단위 테스트 ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn login_packet(src: &str, username: &str) -> Packet {
        let mut p = Packet::new(ip(src), ip("10.0.0.1"));
        p.method = "POST".to_string();
        p.uri = "/login".to_string();
        p.body = format!("username={username}&password=test123")
            .into_bytes();
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
        // 여러 IP에서 동일 username으로 시도
        for i in 0..=USERNAME_IP_THRESHOLD {
            let p = login_packet(&format!("1.2.3.{}", i + 10), "victim");
            let _ = d.detect(&p);
        }
        // 추가 IP에서 시도 → 분산 공격 탐지
        let p = login_packet("1.2.3.99", "victim");
        let result = d.detect(&p);
        assert!(result.is_block());
        assert!(result.reason.contains("distributed attack"));
    }

    #[test]
    fn different_usernames_are_independent() {
        let d = CredentialStuffingDetector::new();
        // user_a로 여러 IP 시도
        for i in 0..=USERNAME_IP_THRESHOLD {
            let p = login_packet(&format!("2.2.2.{}", i), "user_a");
            d.detect(&p);
        }
        // user_b는 영향 없어야 함
        let p = login_packet("3.3.3.3", "user_b");
        assert!(d.detect(&p).is_pass());
    }
}
