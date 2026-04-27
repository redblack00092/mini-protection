use crate::packet::Packet;

// ── Action ─────────────────────────────────────────────────────────────────

/// WAF가 해당 요청에 내릴 수 있는 처분.
/// 파이프라인은 여러 Detector의 결과를 모아 가장 높은 우선순위 Action을 선택한다.
/// 우선순위: Block > Captcha > Challenge > Pass
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    Pass,
    Challenge, // JS 챌린지 발급
    Captcha,   // CAPTCHA 발급
    Block,     // 요청 차단
}

// ── DetectionResult ────────────────────────────────────────────────────────

/// 각 Detector가 반환하는 탐지 결과.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// 권고 처분
    pub action: Action,
    /// 사람이 읽을 수 있는 탐지 사유
    pub reason: String,
    /// 탐지 신뢰도 [0.0, 1.0]
    pub confidence: f32,
}

impl DetectionResult {
    // ── 생성자 ─────────────────────────────────────────────────────────────

    /// 정상 요청 — 통과
    pub fn pass() -> Self {
        Self {
            action: Action::Pass,
            reason: String::from("pass"),
            confidence: 1.0,
        }
    }

    /// 요청 차단
    pub fn block(reason: impl Into<String>, confidence: f32) -> Self {
        Self {
            action: Action::Block,
            reason: reason.into(),
            confidence,
        }
    }

    /// JS 챌린지 발급
    pub fn challenge(reason: impl Into<String>, confidence: f32) -> Self {
        Self {
            action: Action::Challenge,
            reason: reason.into(),
            confidence,
        }
    }

    /// CAPTCHA 발급
    pub fn captcha(reason: impl Into<String>, confidence: f32) -> Self {
        Self {
            action: Action::Captcha,
            reason: reason.into(),
            confidence,
        }
    }

    // ── 헬퍼 ───────────────────────────────────────────────────────────────

    pub fn is_pass(&self) -> bool {
        self.action == Action::Pass
    }

    pub fn is_block(&self) -> bool {
        self.action == Action::Block
    }
}

// ── Detector trait ─────────────────────────────────────────────────────────

/// 모든 탐지 모듈이 구현해야 하는 공통 인터페이스.
///
/// # 설계 원칙
/// - `detect`는 **읽기 전용** — Packet을 변경하지 않는다.
/// - 상태(rate counter, shared memory 등)는 구현체 내부에서 관리한다.
/// - `detect`는 async가 아니다. I/O가 필요한 경우 내부에서
///   `tokio::task::block_in_place` 또는 채널을 사용한다.
pub trait Detector: Send + Sync {
    /// 탐지를 수행하고 결과를 반환한다.
    fn detect(&self, packet: &Packet) -> DetectionResult;

    /// 탐지기 식별자 (로깅·메트릭에 사용)
    fn name(&self) -> &str;
}
