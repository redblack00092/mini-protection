use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};

// ── 봇 블랙리스트 ─────────────────────────────────────────────────────────
// 출처: TrisulNSM/trisul-scripts, ja3er.com, security research
// (hash, 라이브러리 레이블)
const BOT_BLACKLIST: &[(&str, &str)] = &[
    // python-requests / urllib3
    ("c398c55518355639c5a866c15784f969", "python-requests 2.4.3"),
    ("a48c0d5f95b1ef98f560f324fd275da1", "Python urllib3"),
    // curl (OpenSSL 버전별)
    ("764b8952983230b0ac23dbd3741d2bb0", "curl 7.22 Linux"),
    ("9f198208a855994e1b8ec82c892b7d37", "curl 7.43 macOS"),
    ("de4c3d0f370ff1dc78eccd89307bbb28", "curl 7.6x+ OpenSSL"),
];

// ── 브라우저 화이트리스트 ──────────────────────────────────────────────────
// Chrome 110+ / Firefox 114+는 TLS extension 순서를 랜덤화하므로
// 이 목록은 불완전하다. 매칭 시 Pass를 주는 긍정 신호로만 사용한다.
// 매칭 실패가 Block이 되지 않는 이유도 여기에 있다 (false positive 방지).
const BROWSER_WHITELIST: &[&str] = &[
    "c11ab92a9db8107e2a0b0486f35b80b9", // Chrome 124 Windows
    "845db3b4e398789bdeb5b15594360a29", // Chrome 134 macOS
    "b20b44b18b853ef29ab773e921b03422", // Firefox 63
    "2872afed8370401ec6fe92acb53e5301", // Firefox 40
    "773906b0efdefa24a7f2b8eb6985bf37", // Safari 18.3 iOS
    "88770e3ad9e9d85b2e463be2b5c5a026", // Safari 537.78
    "8d2e46c9e2b1ee9b1503cab4905cb3e0", // Edge
];

// ── Ja3FingerprintDetector ────────────────────────────────────────────────

/// X-JA3-Fingerprint 헤더를 기반으로 봇을 탐지한다.
///
/// 탐지 순서:
/// 1. JA3 헤더 없음 → Pass (nginx JA3 모듈 미설정 환경 호환)
/// 2. 알려진 봇 JA3 → Block
/// 3. 브라우저 UA + 화이트리스트 JA3 → Pass
/// 4. 브라우저 UA + 미등록 JA3 → Challenge
///    (Chrome 110+/Firefox 114+는 extension 순서 랜덤화 → Block 시 false positive 급증)
/// 5. 알 수 없는 UA + 미등록 JA3 → Challenge
pub struct Ja3FingerprintDetector;

impl Ja3FingerprintDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for Ja3FingerprintDetector {
    fn name(&self) -> &str {
        "ja3_fingerprint"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        let ja3 = match &packet.ja3_fingerprint {
            None => return DetectionResult::pass(),
            Some(h) => h.as_str(),
        };

        // 1. 봇 블랙리스트 체크
        for &(hash, label) in BOT_BLACKLIST {
            if ja3 == hash {
                return DetectionResult::block(
                    format!("Blacklisted JA3 fingerprint: {ja3} ({label})"),
                    1.0,
                );
            }
        }

        // 2. 브라우저 화이트리스트 — 긍정 신호
        if BROWSER_WHITELIST.contains(&ja3) {
            return DetectionResult::pass();
        }

        // 3. UA/JA3 일관성 체크
        // 봇이 브라우저 UA를 위장해도 JA3는 위조하기 어렵다.
        // 단, 현대 브라우저(Chrome 110+/Firefox 114+)는 JA3를 랜덤화하므로
        // Block 대신 Challenge를 사용해 false positive를 줄인다.
        if is_browser_ua(&packet.user_agent) {
            return DetectionResult::challenge(
                format!(
                    "UA/JA3 mismatch: claims browser but JA3 ({ja3}) not in whitelist"
                ),
                0.5,
            );
        }

        // 4. 알 수 없는 UA + 미등록 JA3 → Challenge
        DetectionResult::challenge(
            format!("Unknown UA and JA3 combination: {ja3}"),
            0.4,
        )
    }
}

/// Mozilla/5.0 기반 주요 브라우저 UA인지 빠르게 확인한다.
/// String 할당 없는 `contains` 체인으로 zero-copy 판별.
fn is_browser_ua(ua: &str) -> bool {
    ua.contains("Mozilla/5.0")
        && (ua.contains("Chrome/")
            || ua.contains("Firefox/")
            || ua.contains("Safari/")
            || ua.contains("Edg/"))
}

#[cfg(test)]
#[path = "../../tests/unit/detectors/ja3_fingerprint.rs"]
mod tests;
