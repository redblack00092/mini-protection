use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};
use regex::RegexSet;

// ── 기본 패턴 ─────────────────────────────────────────────────────────────

/// 즉시 차단할 UA 패턴 (대소문자 무시)
const DEFAULT_BLACKLIST: &[&str] = &[
    // HTTP 라이브러리
    r"(?i)python-requests",
    r"(?i)\bcurl\b",
    r"(?i)\bwget\b",
    r"(?i)scrapy",
    r"(?i)go-http-client",
    r"(?i)\bjava/",
    r"(?i)okhttp",
    // 봇/크롤러 범용 키워드
    r"(?i)\bbot\b",
    r"(?i)\bcrawler\b",
    r"(?i)\bspider\b",
    r"(?i)\bscraper\b",
    // 헤드리스 브라우저 / 자동화
    r"(?i)headless",
    r"(?i)phantomjs",
    r"(?i)selenium",
    // 보안 스캐너
    r"(?i)nikto",
    r"(?i)sqlmap",
    r"(?i)\bnmap\b",
];

/// 정상 브라우저 UA 패턴 — 하나라도 매칭되면 Pass
const DEFAULT_WHITELIST: &[&str] = &[
    // Chrome / Chromium (Mozilla/5.0 … Chrome/NNN)
    r"Mozilla/5\.0 .* Chrome/\d+",
    // Firefox
    r"Mozilla/5\.0 .* Firefox/\d+",
    // Safari (AppleWebKit, Version/NNN Safari)
    r"Mozilla/5\.0 .* Version/\d+.*Safari",
    // Edge (Edg/NNN)
    r"Mozilla/5\.0 .* Edg/\d+",
];

// ── UserAgentConfig ───────────────────────────────────────────────────────

/// config에서 커스텀 패턴을 주입하기 위한 구조체.
/// `None`이면 기본 패턴을 사용한다.
pub struct UserAgentConfig {
    pub blacklist_patterns: Option<Vec<String>>,
    pub whitelist_patterns: Option<Vec<String>>,
}

impl UserAgentConfig {
    pub fn default() -> Self {
        Self {
            blacklist_patterns: None,
            whitelist_patterns: None,
        }
    }
}

// ── UserAgentDetector ─────────────────────────────────────────────────────

/// User-Agent 헤더를 블랙리스트 / 화이트리스트 regex로 검사한다.
///
/// 탐지 순서:
/// 1. UA 비어 있음 → Block
/// 2. 블랙리스트 매칭 → Block
/// 3. 화이트리스트 매칭 → Pass
/// 4. 둘 다 아님 → Challenge
pub struct UserAgentDetector {
    blacklist: RegexSet,
    whitelist: RegexSet,
}

impl UserAgentDetector {
    /// 기본 패턴으로 초기화한다.
    pub fn new() -> Self {
        Self::with_config(UserAgentConfig::default())
    }

    /// config에서 주입된 패턴으로 초기화한다.
    /// 패턴이 없으면 기본값을 사용한다.
    pub fn with_config(cfg: UserAgentConfig) -> Self {
        let bl_patterns: Vec<&str> = cfg
            .blacklist_patterns
            .as_deref()
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_else(|| DEFAULT_BLACKLIST.to_vec());

        let wl_patterns: Vec<&str> = cfg
            .whitelist_patterns
            .as_deref()
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_else(|| DEFAULT_WHITELIST.to_vec());

        Self {
            blacklist: RegexSet::new(bl_patterns).expect("invalid blacklist pattern"),
            whitelist: RegexSet::new(wl_patterns).expect("invalid whitelist pattern"),
        }
    }
}

impl Detector for UserAgentDetector {
    fn name(&self) -> &str {
        "user_agent_detector"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        let ua = packet.user_agent.as_str();

        // 1. 빈 UA
        if ua.is_empty() {
            return DetectionResult::block("Empty User-Agent", 1.0);
        }

        // 2. 블랙리스트
        if self.blacklist.is_match(ua) {
            return DetectionResult::block(
                format!("Blacklisted User-Agent: {ua}"),
                1.0,
            );
        }

        // 3. 화이트리스트
        if self.whitelist.is_match(ua) {
            return DetectionResult::pass();
        }

        // 4. 미분류 → Challenge
        DetectionResult::challenge(
            format!("Unknown User-Agent: {ua}"),
            0.6,
        )
    }
}

#[cfg(test)]
#[path = "../../tests/unit/detectors/user_agent.rs"]
mod tests;
