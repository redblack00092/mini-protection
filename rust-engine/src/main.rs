mod challenge;
mod config;
mod detectors;
mod kafka;
mod packet;
mod pipeline;
mod shared_memory;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    extract::{ConnectInfo, Form, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;

use crate::challenge::{block_response, captcha_response, js_challenge_response};
use crate::detectors::captcha::CaptchaDetector;
use crate::detectors::js_challenge::JsChallengeDetector;
use crate::kafka::{DetectionEvent, KafkaProducer};
use crate::packet::Packet;
use crate::pipeline::Pipeline;
use crate::pipeline::detector::Action;

// ── AppState ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    pipeline: Arc<Pipeline>,
    kafka: Arc<KafkaProducer>,
    cfg: Arc<config::Config>,
    js_detector: Arc<JsChallengeDetector>,
    captcha_detector: Arc<CaptchaDetector>,
    http_client: Client<HttpConnector, Full<Bytes>>,
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// X-Real-IP 헤더에서 클라이언트 IP를 추출한다. 없으면 TCP 연결 IP를 사용한다.
fn extract_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| IpAddr::from_str(s.trim()).ok())
        .unwrap_or_else(|| peer.ip())
}

/// JS 챌린지 응답에서 수집한 screen 크기가 유효한지 확인한다.
fn is_valid_screen_dims(width: u32, height: u32) -> bool {
    width > 0 && height > 0
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// original_uri가 상대 경로인지 확인하여 오픈 리다이렉트를 방지한다.
fn safe_redirect(uri: &str) -> &str {
    if uri.starts_with('/') { uri } else { "/" }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn send_kafka_event(
    state: &AppState,
    src_ip: IpAddr,
    uri: &str,
    reason: &str,
    confidence: f32,
    action: &'static str,
) {
    let event = DetectionEvent {
        timestamp: now_secs(),
        src_ip: src_ip.to_string(),
        uri: uri.to_string(),
        detector: "pipeline".to_string(),
        action: action.to_string(),
        reason: reason.to_string(),
        confidence,
    };
    let kafka = Arc::clone(&state.kafka);
    tokio::spawn(async move {
        if let Err(e) = kafka.send(&event).await {
            tracing::warn!("kafka send failed: {e}");
        }
    });
}

// ── main ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = config::Config::load()?;
    let listen_addr = cfg.listen_addr.clone();
    let js_secret = cfg.js_token_secret.as_bytes().to_vec();

    if cfg.js_token_secret == "change-me-in-production" {
        tracing::warn!("JS_TOKEN_SECRET is using the default value — change before production use");
    }

    let pipeline = Arc::new(Pipeline::new(vec![
        Box::new(detectors::ip_rate_limiter::IpRateLimiter::new()),
        Box::new(detectors::user_agent::UserAgentDetector::new()),
        Box::new(detectors::header_fingerprint::HeaderFingerprintDetector::new()),
        Box::new(detectors::credential_stuffing::CredentialStuffingDetector::new()),
        Box::new(JsChallengeDetector::with_secret(js_secret.clone())),
        Box::new(CaptchaDetector::new()),
    ]));

    let kafka = Arc::new(KafkaProducer::new(&cfg.kafka_brokers, &cfg.kafka_topic)?);
    let js_detector = Arc::new(JsChallengeDetector::with_secret(js_secret));
    let captcha_detector = Arc::new(CaptchaDetector::new());
    let http_client = Client::builder(TokioExecutor::new()).build_http();

    let state = AppState {
        pipeline,
        kafka,
        cfg: Arc::new(cfg),
        js_detector,
        captcha_detector,
        http_client,
    };

    let app = Router::new()
        .route("/__mini-protection/health", get(health_handler))
        .route("/__mini-protection/js-challenge/verify", post(js_verify_handler))
        .route("/__mini-protection/captcha/verify", post(captcha_verify_handler))
        .fallback(proxy_handler)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("WAF engine listening on {}", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

// ── Health ────────────────────────────────────────────────────────────────

/// 헬스체크 엔드포인트 — Docker / 로드밸런서 프로브용.
async fn health_handler() -> Response {
    (StatusCode::OK, "OK").into_response()
}

// ── JS Challenge Verify ───────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct JsVerifyForm {
    #[serde(rename = "screen-width", default)]
    screen_width: u32,
    #[serde(rename = "screen-height", default)]
    screen_height: u32,
    #[serde(default)]
    original_uri: String,
}

/// JS 챌린지 검증: screen 크기 유효성 확인 후 쿠키 발급 및 리다이렉트.
async fn js_verify_handler(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<JsVerifyForm>,
) -> Response {
    if !is_valid_screen_dims(form.screen_width, form.screen_height) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let src_ip = extract_ip(&headers, peer);
    let cookie_value = state.js_detector.issue_cookie(&src_ip.to_string());
    let location = safe_redirect(&form.original_uri).to_string();

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(
            header::SET_COOKIE,
            format!("mini_protection_js_challenge={}; Path=/; HttpOnly; SameSite=Lax", cookie_value),
        )
        .body(axum::body::Body::from(Bytes::new()))
        .unwrap()
}

// ── Captcha Verify ────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct CaptchaVerifyForm {
    #[serde(default)]
    mini_protection_captcha_token: String,
    #[serde(default)]
    original_uri: String,
}

/// CAPTCHA 검증: token 존재 확인 후 쿠키 발급 및 리다이렉트.
async fn captcha_verify_handler(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<CaptchaVerifyForm>,
) -> Response {
    if form.mini_protection_captcha_token.len() <= 20 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let src_ip = extract_ip(&headers, peer);
    let cookie_value = state.captcha_detector.issue_cookie(&src_ip.to_string());
    let location = safe_redirect(&form.original_uri).to_string();

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(
            header::SET_COOKIE,
            format!("mini_protection_captcha_pass={}; Path=/; HttpOnly; SameSite=Lax", cookie_value),
        )
        .body(axum::body::Body::from(Bytes::new()))
        .unwrap()
}

// ── Proxy ─────────────────────────────────────────────────────────────────

/// 인바운드 요청을 Packet으로 변환하여 파이프라인을 실행하고,
/// 결과에 따라 차단/챌린지/CAPTCHA 응답 또는 업스트림 프록시를 수행한다.
async fn proxy_handler(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();

    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            tracing::error!("request body error: {e}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let src_ip = extract_ip(&parts.headers, peer);
    let mut packet = build_packet(&parts, src_ip, &body_bytes);

    // JS 챌린지 쿠키가 유효하면 플래그 설정 (CaptchaDetector가 읽음)
    if let Some(cookie_val) = packet.cookie.get("mini_protection_js_challenge") {
        if state.js_detector.is_cookie_valid(cookie_val, &src_ip.to_string()) {
            packet.js_challenge_passed = true;
        }
    }

    let result = state.pipeline.run(&packet);

    match result.action {
        Action::Pass => proxy_upstream(&state, parts, body_bytes).await,
        Action::Block => {
            send_kafka_event(&state, src_ip, &packet.uri, &result.reason, result.confidence, "Block");
            block_response(&result.reason)
        }
        Action::Challenge => {
            send_kafka_event(&state, src_ip, &packet.uri, &result.reason, result.confidence, "Challenge");
            js_challenge_response(&packet.uri)
        }
        Action::Captcha => {
            if state.cfg.captcha_site_key.is_empty() {
                proxy_request(&state, packet).await
            } else {
                send_kafka_event(&state, src_ip, &packet.uri, &result.reason, result.confidence, "Captcha");
                captcha_response(&packet.uri, &state.cfg.captcha_site_key)
            }
        }
    }
}

fn build_packet(parts: &axum::http::request::Parts, src_ip: IpAddr, body: &Bytes) -> Packet {
    let dst_ip: IpAddr = "0.0.0.0".parse().unwrap();
    let mut packet = Packet::new(src_ip, dst_ip);

    packet.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    packet.method = parts.method.to_string();
    packet.uri = parts
        .uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/".to_string());
    packet.http_version = format!("{:?}", parts.version);
    packet.user_agent = header_str(&parts.headers, "user-agent");
    packet.host = header_str(&parts.headers, "host");
    packet.referer = header_str(&parts.headers, "referer");

    for (name, value) in parts.headers.iter() {
        if let Ok(v) = value.to_str() {
            packet.headers.insert(name.to_string(), v.to_string());
        }
    }

    if let Some(cookie_header) = parts.headers.get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            packet.cookie = Packet::parse_cookies(cookie_str);
        }
    }

    packet.body = body.to_vec();
    packet
}

fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

async fn proxy_upstream(
    state: &AppState,
    parts: axum::http::request::Parts,
    body_bytes: Bytes,
) -> Response {
    let base = state.cfg.upstream_url.trim_end_matches('/');
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_uri = format!("{base}{path_and_query}");

    let mut builder = hyper::Request::builder()
        .method(&parts.method)
        .uri(&upstream_uri);

    for (name, value) in parts.headers.iter() {
        if !is_hop_by_hop(name.as_str()) {
            builder = builder.header(name, value);
        }
    }

    let upstream_req = match builder.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("upstream request build failed: {e}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let upstream_resp = match state.http_client.request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("upstream request failed: {e}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let (mut resp_parts, resp_body) = upstream_resp.into_parts();

    let resp_bytes = match resp_body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            tracing::error!("upstream response body error: {e}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    for hop in [
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade",
    ] {
        resp_parts.headers.remove(hop);
    }

    Response::from_parts(resp_parts, axum::body::Body::from(resp_bytes))
}

// ── 단위 테스트 ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
}

// ── 통합 테스트 ───────────────────────────────────────────────────────────

#[cfg(test)]
mod integration_tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
use tower::util::ServiceExt;

    fn base_state() -> AppState {
        // rdkafka producer 생성은 실제 브로커 없이도 성공한다 (연결은 lazy)
        let kafka = KafkaProducer::new("localhost:29999", "test")
            .expect("KafkaProducer creation must not require a live broker");
        AppState {
            pipeline: Arc::new(Pipeline::new(vec![])), // 비어있으면 모두 Pass
            kafka: Arc::new(kafka),
            cfg: Arc::new(config::Config {
                listen_addr: "0.0.0.0:8080".to_string(),
                upstream_url: "http://127.0.0.1:29998".to_string(), // 존재하지 않는 upstream
                kafka_brokers: "localhost:29999".to_string(),
                kafka_topic: "test".to_string(),
                js_token_secret: "test-secret".to_string(),
                captcha_site_key: String::new(),
            }),
            js_detector: Arc::new(JsChallengeDetector::with_secret(b"test-secret".to_vec())),
            captcha_detector: Arc::new(CaptchaDetector::new()),
            http_client: Client::builder(TokioExecutor::new()).build_http(),
        }
    }

    fn test_app(state: AppState) -> Router {
        Router::new()
            .route("/__mini-protection/health", get(health_handler))
            .route("/__mini-protection/js-challenge/verify", post(js_verify_handler))
            .route("/__mini-protection/captcha/verify", post(captcha_verify_handler))
            .fallback(proxy_handler)
            .with_state(state)
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))))
    }

    fn form_req(uri: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    // ── health ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn health_returns_200() {
        let resp = test_app(base_state())
            .oneshot(Request::builder().uri("/__mini-protection/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── js_verify ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn js_verify_valid_dims_redirects_with_cookie() {
        let resp = test_app(base_state())
            .oneshot(form_req(
                "/__mini-protection/js-challenge/verify",
                "screen-width=1920&screen-height=1080&original_uri=/protected",
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers().get("location").unwrap(), "/protected");
        let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(cookie.contains("mini_protection_js_challenge="));
        assert!(cookie.contains("HttpOnly"));
    }

    #[tokio::test]
    async fn js_verify_zero_width_returns_400() {
        let resp = test_app(base_state())
            .oneshot(form_req(
                "/__mini-protection/js-challenge/verify",
                "screen-width=0&screen-height=1080&original_uri=/",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn js_verify_zero_height_returns_400() {
        let resp = test_app(base_state())
            .oneshot(form_req(
                "/__mini-protection/js-challenge/verify",
                "screen-width=1920&screen-height=0&original_uri=/",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn js_verify_missing_dims_defaults_to_400() {
        // dims 없으면 serde default(0) → is_valid_screen_dims 실패
        let resp = test_app(base_state())
            .oneshot(form_req("/__mini-protection/js-challenge/verify", "original_uri=/"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn js_verify_external_uri_redirects_to_root() {
        let resp = test_app(base_state())
            .oneshot(form_req(
                "/__mini-protection/js-challenge/verify",
                "screen-width=1920&screen-height=1080&original_uri=https://evil.com",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
    }

    // ── captcha_verify ────────────────────────────────────────────────────

    #[tokio::test]
    async fn captcha_verify_valid_token_redirects_with_cookie() {
        let token = "a".repeat(100);
        let body = format!("mini_protection_captcha_token={}&original_uri=/dashboard", token);
        let resp = test_app(base_state())
            .oneshot(form_req("/__mini-protection/captcha/verify", &body))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers().get("location").unwrap(), "/dashboard");
        let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(cookie.contains("mini_protection_captcha_pass="));
        assert!(cookie.contains("HttpOnly"));
    }

    #[tokio::test]
    async fn captcha_verify_short_token_returns_400() {
        let resp = test_app(base_state())
            .oneshot(form_req(
                "/__mini-protection/captcha/verify",
                "mini_protection_captcha_token=tooshort&original_uri=/",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn captcha_verify_empty_token_returns_400() {
        let resp = test_app(base_state())
            .oneshot(form_req("/__mini-protection/captcha/verify", "original_uri=/"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── proxy ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn proxy_pass_with_unreachable_upstream_returns_502() {
        // 빈 파이프라인(Pass) + 존재하지 않는 upstream → 502
        let resp = test_app(base_state())
            .oneshot(Request::builder().uri("/some/path").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn proxy_block_action_returns_403() {
        use crate::pipeline::detector::{DetectionResult, Detector};

        struct AlwaysBlock;
        impl Detector for AlwaysBlock {
            fn detect(&self, _: &Packet) -> DetectionResult {
                DetectionResult::block("test block", 1.0)
            }
            fn name(&self) -> &str { "always_block" }
        }

        let mut state = base_state();
        state.pipeline = Arc::new(Pipeline::new(vec![Box::new(AlwaysBlock)]));

        let resp = test_app(state)
            .oneshot(Request::builder().uri("/attack").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn proxy_challenge_action_returns_js_challenge_html() {
        use crate::pipeline::detector::{DetectionResult, Detector};

        struct AlwaysChallenge;
        impl Detector for AlwaysChallenge {
            fn detect(&self, _: &Packet) -> DetectionResult {
                DetectionResult::challenge("js required", 0.7)
            }
            fn name(&self) -> &str { "always_challenge" }
        }

        let mut state = base_state();
        state.pipeline = Arc::new(Pipeline::new(vec![Box::new(AlwaysChallenge)]));

        let resp = test_app(state)
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("/__mini-protection/js-challenge/verify"));
        assert!(html.contains("window.innerWidth"));
    }

    #[tokio::test]
    async fn proxy_captcha_action_returns_captcha_html() {
        use crate::pipeline::detector::{DetectionResult, Detector};

        struct AlwaysCaptcha;
        impl Detector for AlwaysCaptcha {
            fn detect(&self, _: &Packet) -> DetectionResult {
                DetectionResult::captcha("captcha required", 0.9)
            }
            fn name(&self) -> &str { "always_captcha" }
        }

        let mut state = base_state();
        state.pipeline = Arc::new(Pipeline::new(vec![Box::new(AlwaysCaptcha)]));

        let resp = test_app(state)
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("/__mini-protection/captcha/verify"));
        assert!(html.contains("mini_protection_captcha_token"));
    }
}
