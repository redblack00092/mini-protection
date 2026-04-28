use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};
use std::collections::HashSet;
use std::fs;

const BLACKLIST_PATH: &str = "/etc/mini-protection/ja3_blacklist.txt";
const WHITELIST_PATH: &str = "/etc/mini-protection/ja3_whitelist.txt";

pub struct Ja3FingerprintDetector {
    blacklist: HashSet<String>,
    whitelist: HashSet<String>,
}

fn load_set(path: &str) -> HashSet<String> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("JA3 list not loaded from {path}: {e}");
            return HashSet::new();
        }
    };
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let hash = line.split_whitespace().next()?;
            (hash.len() == 32).then(|| hash.to_string())
        })
        .collect()
}

fn is_browser_ua(ua: &str) -> bool {
    ua.contains("Mozilla/5.0")
        && (ua.contains("Chrome/")
            || ua.contains("Firefox/")
            || ua.contains("Safari/")
            || ua.contains("Edg/"))
}

impl Ja3FingerprintDetector {
    pub fn new() -> Self {
        let blacklist = load_set(BLACKLIST_PATH);
        let whitelist = load_set(WHITELIST_PATH);
        tracing::info!(
            "JA3 loaded: {} blacklist, {} whitelist entries",
            blacklist.len(),
            whitelist.len()
        );
        Self { blacklist, whitelist }
    }

    #[cfg(test)]
    fn with_sets(blacklist: HashSet<String>, whitelist: HashSet<String>) -> Self {
        Self { blacklist, whitelist }
    }
}

impl Detector for Ja3FingerprintDetector {
    fn name(&self) -> &str {
        "ja3_fingerprint"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        let ja3 = match &packet.ja3_fingerprint {
            Some(h) if !h.is_empty() => h.as_str(),
            _ => return DetectionResult::pass(),
        };

        // 1. 블랙리스트 → Block
        if self.blacklist.contains(ja3) {
            return DetectionResult::block(format!("Blacklisted JA3: {ja3}"), 1.0);
        }

        // 2. 화이트리스트 + 브라우저 UA → Pass
        //    화이트리스트만으로 Pass 시 UA를 위조한 봇이 우회 가능하므로 UA 검증 추가
        if self.whitelist.contains(ja3) && is_browser_ua(&packet.user_agent) {
            return DetectionResult::pass();
        }

        // 3. 나머지 → Challenge
        //    - 화이트리스트 JA3 + 비브라우저 UA: 브라우저 TLS를 흉내낸 봇 의심
        //    - 미등록 JA3 + 브라우저 UA: Chrome 110+/Firefox 114+ 랜덤화 가능성
        //    - 미등록 JA3 + 비브라우저 UA: 알 수 없는 클라이언트
        let reason = if self.whitelist.contains(ja3) {
            format!("JA3 in whitelist but non-browser UA: {ja3}")
        } else if is_browser_ua(&packet.user_agent) {
            format!("Browser UA but JA3 ({ja3}) not in whitelist")
        } else {
            format!("Unknown UA and JA3: {ja3}")
        };
        DetectionResult::challenge(reason, 0.5)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/detectors/ja3_fingerprint.rs"]
mod tests;
