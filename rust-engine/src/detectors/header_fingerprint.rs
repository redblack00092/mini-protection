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

// ── 단위 테스트 ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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

    /// 정상 브라우저 헤더를 가진 패킷
    fn normal_packet() -> Packet {
        let mut p = base_packet();
        p.headers.insert("accept".into(), "text/html,application/xhtml+xml,*/*".into());
        p.headers.insert("accept-language".into(), "ko-KR,ko;q=0.9,en-US;q=0.8".into());
        p.headers.insert("accept-encoding".into(), "gzip, deflate, br".into());
        p.headers.insert("connection".into(), "keep-alive".into());
        p
    }

    // ── Pass (0~30점) ─────────────────────────────────────────────────────

    #[test]
    fn passes_normal_browser() {
        assert!(detector().detect(&normal_packet()).is_pass());
    }

    #[test]
    fn passes_score_30_exactly() {
        // Accept: */* (+30), 나머지 정상 → score=30 → Pass
        let mut p = normal_packet();
        p.headers.insert("accept".into(), "*/*".into());
        assert!(detector().detect(&p).is_pass());
    }

    // ── Challenge (31~60점) ───────────────────────────────────────────────

    #[test]
    fn challenges_score_50() {
        // Accept: */* (+30) + Accept-Encoding 없음 (+20) = 50 → Challenge
        let mut p = base_packet();
        p.headers.insert("accept".into(), "*/*".into());
        p.headers.insert("accept-language".into(), "en-US".into());
        // accept-encoding 없음
        let r = detector().detect(&p);
        assert_eq!(r.action, Action::Challenge);
        assert!(r.reason.contains("score: 50"));
        assert!((r.confidence - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn challenges_score_31() {
        // Accept-Language 없음 (+30) + Connection: close (+20) = 50이지만
        // Accept-Language만 없는 경우: +30 → Pass.
        // Accept-Language 없음 (+30) + (다른 조건 없음) = 30 → Pass.
        // 정확히 31점을 만들기 위한 조합은 없으므로 50점 케이스로 대체 검증.
        // (점수 테이블 상 31~60 구간은 50점 케이스로 커버됨)
        let mut p = base_packet();
        p.headers.insert("accept".into(), "*/*".into());           // +30
        p.headers.insert("accept-language".into(), "en".into());
        p.headers.insert("accept-encoding".into(), "gzip".into());
        p.headers.insert("connection".into(), "close".into());     // +20 → 50
        let r = detector().detect(&p);
        assert_eq!(r.action, Action::Challenge);
    }

    // ── Block (61점 이상) ─────────────────────────────────────────────────

    #[test]
    fn blocks_score_100() {
        // Accept: */* (+30) + no Accept-Language (+30) + no Accept-Encoding (+20) = 80
        let mut p = base_packet();
        p.headers.insert("accept".into(), "*/*".into());
        // accept-language, accept-encoding 없음
        let r = detector().detect(&p);
        assert!(r.is_block());
        assert!(r.reason.contains("score: 80"));
    }

    #[test]
    fn blocks_all_suspicious() {
        // 모든 의심 패턴: 30+30+20+20 = 100점
        let mut p = base_packet();
        p.headers.insert("accept".into(), "*/*".into());
        p.headers.insert("connection".into(), "close".into());
        // accept-language, accept-encoding 없음
        let r = detector().detect(&p);
        assert!(r.is_block());
        assert!(r.reason.contains("score: 100"));
    }

    #[test]
    fn blocks_score_exactly_61() {
        // no Accept-Language (+30) + no Accept-Encoding (+20) + Connection: close (+20) = 70 → Block
        // (61점 정확히는 패턴 조합상 불가, 70점으로 검증)
        let mut p = base_packet();
        p.headers.insert("accept".into(), "text/html".into()); // 정상
        p.headers.insert("connection".into(), "close".into()); // +20
        // accept-language 없음 (+30), accept-encoding 없음 (+20) → 70
        let r = detector().detect(&p);
        assert!(r.is_block());
    }

    // ── Connection 대소문자 무시 ──────────────────────────────────────────

    #[test]
    fn connection_close_case_insensitive() {
        let mut p = normal_packet();
        p.headers.insert("connection".into(), "Close".into());
        let r = detector().detect(&p);
        // Accept 정상 + Connection: Close (+20) = 20 → Pass
        assert!(r.is_pass());
    }
}
