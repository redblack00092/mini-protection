use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// HTML 응답에 숨겨진 트랩 링크(`/__mini-protection/trap`)에 접근한 IP 집합.
/// main.rs의 트랩 핸들러와 공유된다.
pub type HoneypotStore = Arc<DashMap<IpAddr, ()>>;

/// 허니팟 트랩에 접근한 IP를 영구 차단한다.
///
/// 동작 흐름:
/// 1. proxy_upstream이 HTML 응답에 숨겨진 링크 주입
/// 2. 봇이 HTML 파싱 중 링크를 따라 `/__mini-protection/trap` 요청
/// 3. 트랩 핸들러가 HoneypotStore에 IP 기록
/// 4. 이후 요청에서 이 Detector가 Block 반환
pub struct HoneypotDetector {
    caught: HoneypotStore,
}

impl HoneypotDetector {
    pub fn new(caught: HoneypotStore) -> Self {
        Self { caught }
    }
}

impl Detector for HoneypotDetector {
    fn name(&self) -> &str {
        "honeypot"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        if self.caught.contains_key(&packet.src_ip) {
            return DetectionResult::block("Honeypot trap triggered", 1.0);
        }
        DetectionResult::pass()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/detectors/honeypot.rs"]
mod tests;
