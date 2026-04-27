use super::*;
use axum::http::HeaderValue;

fn peer(ip: &str) -> SocketAddr {
    format!("{ip}:8080").parse().unwrap()
}

#[test]
fn extract_ip_uses_x_real_ip_header() {
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", HeaderValue::from_static("5.6.7.8"));
    assert_eq!(
        extract_ip(&headers, peer("1.2.3.4")),
        "5.6.7.8".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn extract_ip_falls_back_to_peer_addr() {
    assert_eq!(
        extract_ip(&HeaderMap::new(), peer("1.2.3.4")),
        "1.2.3.4".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn extract_ip_ignores_invalid_x_real_ip() {
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", HeaderValue::from_static("not-an-ip"));
    assert_eq!(
        extract_ip(&headers, peer("1.2.3.4")),
        "1.2.3.4".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn screen_dims_valid_for_positive_values() {
    assert!(is_valid_screen_dims(1920, 1080));
    assert!(is_valid_screen_dims(1, 1));
}

#[test]
fn screen_dims_invalid_when_zero() {
    assert!(!is_valid_screen_dims(0, 1080));
    assert!(!is_valid_screen_dims(1920, 0));
    assert!(!is_valid_screen_dims(0, 0));
}

#[test]
fn safe_redirect_preserves_absolute_paths() {
    assert_eq!(safe_redirect("/foo/bar"), "/foo/bar");
    assert_eq!(safe_redirect("/"), "/");
    assert_eq!(safe_redirect("/?q=1"), "/?q=1");
}

#[test]
fn safe_redirect_blocks_external_urls() {
    assert_eq!(safe_redirect("https://evil.com"), "/");
    assert_eq!(safe_redirect("http://evil.com/steal"), "/");
    assert_eq!(safe_redirect(""), "/");
}

#[test]
fn hop_by_hop_headers_are_identified() {
    assert!(is_hop_by_hop("connection"));
    assert!(is_hop_by_hop("transfer-encoding"));
    assert!(is_hop_by_hop("upgrade"));
    assert!(!is_hop_by_hop("content-type"));
    assert!(!is_hop_by_hop("authorization"));
    assert!(!is_hop_by_hop("x-real-ip"));
}
