use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};

// ── 점수 임계값 ───────────────────────────────────────────────────────────

const SCORE_CHALLENGE: u32 = 31;
const SCORE_BLOCK: u32 = 61;

// ── 개별 의심 패턴 점수 ───────────────────────────────────────────────────

const SCORE_ACCEPT_WILDCARD: u32 = 30; // Accept: */* 만
const SCORE_NO_ACCEPT_LANGUAGE: u32 = 30; // Accept-Language 없음
const SCORE_NO_ACCEPT_ENCODING: u32 = 20; // Accept-Encoding 없음
const SCORE_CONNECTION_CLOSE: u32 = 20; // Connection: close

// ── HeaderFingerprintDetector ─────────────────────────────────────────────

/// HTTP 헤더 조합(존재 여부, 값 패턴)으로 봇 클라이언트를 식별한다.
///
/// 각 의심 패턴에 점수를 부여하고 합산:
/// - 0~30점  → Pass
/// - 31~60점 → Challenge (confidence = score / 100)
/// - 61점~   → Block
pub struct HeaderFingerprintDetector;

impl HeaderFingerprintDetector {
    pub fn new() -> Self {
        Self
    }

    /// 헤더 조합을 검사하여 의심 점수를 반환한다.
    fn score(&self, packet: &Packet) -> u32 {
        let mut score: u32 = 0;
        let headers = &packet.headers;

        // Accept: */* 만 존재 (text/html 등 구체적 타입 없음)
        if let Some(accept) = headers.get("accept") {
            let trimmed = accept.trim();
            if trimmed == "*/*" {
                score += SCORE_ACCEPT_WILDCARD;
            }
        }

        // Accept-Language 헤더 없음
        if !headers.contains_key("accept-language") {
            score += SCORE_NO_ACCEPT_LANGUAGE;
        }

        // Accept-Encoding 헤더 없음
        if !headers.contains_key("accept-encoding") {
            score += SCORE_NO_ACCEPT_ENCODING;
        }

        // Connection: close
        if let Some(conn) = headers.get("connection") {
            if conn.trim().eq_ignore_ascii_case("close") {
                score += SCORE_CONNECTION_CLOSE;
            }
        }

        score
    }
}

impl Detector for HeaderFingerprintDetector {
    fn name(&self) -> &str {
        "header_fingerprint"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        let score = self.score(packet);

        if score >= SCORE_BLOCK {
            return DetectionResult::block(
                format!("Suspicious header pattern (score: {score})"),
                1.0,
            );
        }

        if score >= SCORE_CHALLENGE {
            let confidence = (score as f32) / 100.0;
            return DetectionResult::challenge(
                format!("Suspicious header pattern (score: {score})"),
                confidence,
            );
        }

        DetectionResult::pass()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/detectors/header_fingerprint.rs"]
mod tests;
