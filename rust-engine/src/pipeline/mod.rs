pub mod detector;

use crate::packet::Packet;
use detector::{Action, DetectionResult, Detector};
use std::sync::Arc;

// ── Pipeline ──────────────────────────────────────────────────────────────

/// 등록된 Detector를 순서대로 실행하는 파이프라인.
///
/// 설계 원칙:
/// - Packet은 &참조로만 전달 (zero-copy)
/// - 각 Detector는 독립적으로 실행
/// - Block이 나오면 즉시 반환 (early exit)
/// - 그 외는 우선순위(Block > Captcha > Challenge > Pass)에 따라 최종 결과 선택
pub struct Pipeline {
    detectors: Vec<Arc<dyn Detector>>,
}

impl Pipeline {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self {
            detectors: detectors.into_iter().map(Arc::from).collect(),
        }
    }

    /// 파이프라인 실행:
    /// 1. 순서대로 각 Detector 실행
    /// 2. Block 발생 시 즉시 반환 (성능 최적화)
    /// 3. 최종 결과는 우선순위가 가장 높은 Action 반환
    pub fn run(&self, packet: &Packet) -> DetectionResult {
        let mut worst = DetectionResult::pass();

        for detector in &self.detectors {
            let result = detector.detect(packet);

            tracing::debug!(
                detector = detector.name(),
                action = ?result.action,
                reason = %result.reason,
                confidence = result.confidence,
                "detection result"
            );

            // Block은 즉시 반환 (이후 탐지 불필요)
            if result.action == Action::Block {
                return result;
            }

            // 우선순위가 높은 결과 유지
            if result.action > worst.action {
                worst = result;
            }
        }

        worst
    }

    /// 등록된 Detector 이름 목록 반환
    pub fn detector_names(&self) -> Vec<&str> {
        self.detectors.iter().map(|d| d.name()).collect()
    }
}

// ── 단위 테스트 ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::detector::{Action, DetectionResult, Detector};
    use std::net::IpAddr;

    // 테스트용 더미 Detector
    struct AlwaysPass;
    struct AlwaysBlock;
    struct AlwaysChallenge;
    struct AlwaysCaptcha;

    impl Detector for AlwaysPass {
        fn detect(&self, _: &Packet) -> DetectionResult { DetectionResult::pass() }
        fn name(&self) -> &str { "always_pass" }
    }
    impl Detector for AlwaysBlock {
        fn detect(&self, _: &Packet) -> DetectionResult {
            DetectionResult::block("test block", 1.0)
        }
        fn name(&self) -> &str { "always_block" }
    }
    impl Detector for AlwaysChallenge {
        fn detect(&self, _: &Packet) -> DetectionResult {
            DetectionResult::challenge("test challenge", 0.5)
        }
        fn name(&self) -> &str { "always_challenge" }
    }
    impl Detector for AlwaysCaptcha {
        fn detect(&self, _: &Packet) -> DetectionResult {
            DetectionResult::captcha("test captcha", 0.8)
        }
        fn name(&self) -> &str { "always_captcha" }
    }

    fn test_packet() -> Packet {
        Packet::new(
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            "10.0.0.1".parse::<IpAddr>().unwrap(),
        )
    }

    #[test]
    fn passes_when_all_pass() {
        let p = Pipeline::new(vec![
            Box::new(AlwaysPass),
            Box::new(AlwaysPass),
        ]);
        assert!(p.run(&test_packet()).is_pass());
    }

    #[test]
    fn blocks_when_any_blocks() {
        let p = Pipeline::new(vec![
            Box::new(AlwaysPass),
            Box::new(AlwaysBlock),
            Box::new(AlwaysPass),
        ]);
        let result = p.run(&test_packet());
        assert!(result.is_block());
        assert_eq!(result.reason, "test block");
    }

    #[test]
    fn block_early_exits_pipeline() {
        // Block 이후 Detector는 실행되지 않아야 함
        // AlwaysBlock → AlwaysChallenge 순서지만 결과는 Block
        let p = Pipeline::new(vec![
            Box::new(AlwaysBlock),
            Box::new(AlwaysChallenge),
        ]);
        let result = p.run(&test_packet());
        assert_eq!(result.action, Action::Block);
        assert_eq!(result.reason, "test block");
    }

    #[test]
    fn returns_highest_priority_non_block() {
        // Challenge < Captcha → Captcha 반환
        let p = Pipeline::new(vec![
            Box::new(AlwaysChallenge),
            Box::new(AlwaysCaptcha),
            Box::new(AlwaysPass),
        ]);
        let result = p.run(&test_packet());
        assert_eq!(result.action, Action::Captcha);
    }

    #[test]
    fn challenge_wins_over_pass() {
        let p = Pipeline::new(vec![
            Box::new(AlwaysPass),
            Box::new(AlwaysChallenge),
        ]);
        let result = p.run(&test_packet());
        assert_eq!(result.action, Action::Challenge);
    }

    #[test]
    fn empty_pipeline_passes() {
        let p = Pipeline::new(vec![]);
        assert!(p.run(&test_packet()).is_pass());
    }

    #[test]
    fn detector_names_returns_all() {
        let p = Pipeline::new(vec![
            Box::new(AlwaysPass),
            Box::new(AlwaysBlock),
        ]);
        let names = p.detector_names();
        assert_eq!(names, vec!["always_pass", "always_block"]);
    }
}
