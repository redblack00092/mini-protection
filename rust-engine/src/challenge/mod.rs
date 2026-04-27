use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};

/// JS 챌린지 응답 — window.innerWidth/Height를 수집하는 hidden form.
/// 봇은 JS를 실행하지 못해 form submit이 불가능하다.
pub fn js_challenge_response(original_uri: &str) -> Response {
    let escaped = html_escape(original_uri);
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Security Check</title></head>
<body>
<form id="f" method="POST" action="/__mini-protection/js-challenge/verify">
  <input type="hidden" name="original_uri" value="{escaped}">
  <input type="hidden" name="screen-width" id="sw">
  <input type="hidden" name="screen-height" id="sh">
</form>
<script>
  document.getElementById('sw').value=window.innerWidth;
  document.getElementById('sh').value=window.innerHeight;
  document.getElementById('f').submit();
</script>
</body>
</html>"#
    );
    Html(html).into_response()
}

/// reCAPTCHA v2 검증 페이지.
/// WAF 서버는 외부 통신 없음 — 클라이언트 브라우저가 Google JS를 직접 로드한다.
pub fn captcha_response(original_uri: &str, site_key: &str) -> Response {
    let escaped_uri = html_escape(original_uri);
    let escaped_key = html_escape(site_key);
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"><title>CAPTCHA Verification</title>
  <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
<form method="POST" action="/__mini-protection/captcha/verify" id="cf">
  <input type="hidden" name="original_uri" value="{escaped_uri}">
  <input type="hidden" name="mini_protection_captcha_token" id="ct">
  <div class="g-recaptcha" data-sitekey="{escaped_key}" data-callback="onDone"></div>
</form>
<script>
function onDone(t){{document.getElementById('ct').value=t;document.getElementById('cf').submit();}}
</script>
</body>
</html>"#
    );
    Html(html).into_response()
}

/// 403 차단 응답 (HTML).
pub fn block_response(reason: &str) -> Response {
    let escaped = html_escape(reason);
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden</title>
  <style>
    body {{ font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }}
    .box {{ text-align: center; padding: 40px; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.1); }}
    h1 {{ font-size: 48px; margin: 0 0 8px; color: #e53e3e; }}
    p {{ color: #555; margin: 4px 0; }}
    small {{ color: #999; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>403</h1>
    <p>Access Denied</p>
    <small>{escaped}</small>
  </div>
</body>
</html>"#
    );
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

// ── 단위 테스트 ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn block_response_is_403() {
        let resp = block_response("test reason");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn block_response_has_json_content_type() {
        let resp = block_response("reason");
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
            "application/json"
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
}
