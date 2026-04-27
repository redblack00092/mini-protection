use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};

// 스캐너/취약점 열거 경로 — 정상 브라우저 사용자가 절대 접근하지 않는 경로들.
// 일치 시 즉시 Block (confidence 1.0).
const SCANNER_PATHS: &[&str] = &[
    // 환경 설정 / 시크릿 노출
    "/.env",
    "/.git",
    "/.htaccess",
    "/.htpasswd",
    "/.aws",
    "/.ssh",
    "/.DS_Store",
    "/web.config",
    // WordPress
    "/wp-admin",
    "/wp-login.php",
    "/wp-content",
    "/wp-includes",
    "/xmlrpc.php",
    // DB 관리 도구
    "/phpmyadmin",
    "/pma",
    "/adminer",
    "/adminer.php",
    // 공통 CMS / 설치 파일
    "/admin.php",
    "/config.php",
    "/configuration.php",
    "/setup.php",
    "/install.php",
    // 웹쉘
    "/shell.php",
    "/c99.php",
    "/r57.php",
    // LFI 대상 경로
    "/etc/passwd",
    "/proc/self",
];

/// 알려진 스캐너/취약점 열거 경로 접근을 차단한다.
///
/// 매칭 규칙: URI 경로(쿼리 제외)가 패턴과 정확히 일치하거나
/// 패턴 뒤에 `/`가 오는 경우 매칭 (예: `/wp-admin/post.php` → 매칭).
pub struct PathScannerDetector;

impl PathScannerDetector {
    pub fn new() -> Self {
        Self
    }

    fn is_scanner_path(uri: &str) -> bool {
        // 쿼리 파라미터 제거 후 소문자 변환
        let path = uri.split('?').next().unwrap_or(uri).to_lowercase();
        SCANNER_PATHS.iter().any(|p| {
            path == *p || path.starts_with(&format!("{}/", p))
        })
    }
}

impl Detector for PathScannerDetector {
    fn name(&self) -> &str {
        "path_scanner"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        if Self::is_scanner_path(&packet.uri) {
            return DetectionResult::block(
                format!("Scanner path detected: {}", packet.uri),
                1.0,
            );
        }
        DetectionResult::pass()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/detectors/path_scanner.rs"]
mod tests;
