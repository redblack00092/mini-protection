use super::*;
use std::net::IpAddr;

fn detector() -> PathScannerDetector {
    PathScannerDetector::new()
}

fn packet(uri: &str) -> Packet {
    let mut p = Packet::new(
        "1.2.3.4".parse::<IpAddr>().unwrap(),
        "10.0.0.1".parse::<IpAddr>().unwrap(),
    );
    p.uri = uri.to_string();
    p
}

#[test]
fn blocks_env_file() {
    assert!(detector().detect(&packet("/.env")).is_block());
}

#[test]
fn blocks_git_config() {
    assert!(detector().detect(&packet("/.git/config")).is_block());
}

#[test]
fn blocks_wp_admin_subpath() {
    assert!(detector().detect(&packet("/wp-admin/admin.php")).is_block());
}

#[test]
fn blocks_phpmyadmin() {
    assert!(detector().detect(&packet("/phpmyadmin")).is_block());
}

#[test]
fn blocks_with_query_string() {
    assert!(detector().detect(&packet("/.env?foo=bar")).is_block());
}

#[test]
fn blocks_uppercase_path() {
    assert!(detector().detect(&packet("/.ENV")).is_block());
}

#[test]
fn passes_normal_path() {
    assert!(detector().detect(&packet("/")).is_pass());
    assert!(detector().detect(&packet("/dashboard")).is_pass());
    assert!(detector().detect(&packet("/api/v1/users")).is_pass());
}

#[test]
fn passes_git_repo_path_in_gitea() {
    assert!(detector().detect(&packet("/alice/my-repo.git")).is_pass());
}
