use super::*;
use axum::http::StatusCode;

#[test]
fn block_response_is_403() {
    let resp = block_response("test reason");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[test]
fn block_response_content_type_is_html() {
    let resp = block_response("reason");
    assert_eq!(
        resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );
}

#[test]
fn js_challenge_response_is_200() {
    let resp = js_challenge_response("/protected");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[test]
fn captcha_response_is_200() {
    let resp = captcha_response("/protected", "my-site-key");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[test]
fn html_escape_encodes_all_special_chars() {
    assert_eq!(html_escape("<script>"), "&lt;script&gt;");
    assert_eq!(html_escape("a&b"), "a&amp;b");
    assert_eq!(html_escape("\"x\""), "&quot;x&quot;");
    assert_eq!(html_escape("'y'"), "&#x27;y&#x27;");
    assert_eq!(html_escape("normal"), "normal");
}

#[test]
fn html_escape_handles_empty_string() {
    assert_eq!(html_escape(""), "");
}
