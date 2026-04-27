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

#[cfg(test)]
#[path = "../../tests/unit/pipeline.rs"]
mod tests;
