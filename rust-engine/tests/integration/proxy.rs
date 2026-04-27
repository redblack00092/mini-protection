use super::*;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::Request;
use tower::util::ServiceExt;

fn base_state() -> AppState {
    let kafka = KafkaProducer::new("localhost:29999", "test")
        .expect("KafkaProducer creation must not require a live broker");
    AppState {
        pipeline: Arc::new(Pipeline::new(vec![])),
        kafka: Arc::new(kafka),
        cfg: Arc::new(config::Config {
            listen_addr: "0.0.0.0:8080".to_string(),
            upstream_url: "http://127.0.0.1:29998".to_string(),
            kafka_brokers: "localhost:29999".to_string(),
            kafka_topic: "test".to_string(),
            js_token_secret: "test-secret".to_string(),
            captcha_site_key: String::new(),
        }),
        js_detector: Arc::new(JsChallengeDetector::with_secret(b"test-secret".to_vec())),
        captcha_detector: Arc::new(CaptchaDetector::new()),
        http_client: Client::builder(TokioExecutor::new()).build_http(),
        honeypot_caught: Arc::new(DashMap::new()),
    }
}

fn test_app(state: AppState) -> Router {
    Router::new()
        .route("/__mini-protection/health", get(health_handler))
        .route("/__mini-protection/js-challenge/verify", post(js_verify_handler))
        .route("/__mini-protection/captcha/verify", post(captcha_verify_handler))
        .route("/__mini-protection/trap", get(honeypot_trap_handler))
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

#[tokio::test]
async fn health_returns_200() {
    let resp = test_app(base_state())
        .oneshot(Request::builder().uri("/__mini-protection/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

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

#[tokio::test]
async fn proxy_pass_with_unreachable_upstream_returns_502() {
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
    // captcha_site_key가 있어야 bypass 대신 실제 captcha 페이지 반환
    state.cfg = Arc::new(config::Config {
        listen_addr: "0.0.0.0:8080".to_string(),
        upstream_url: "http://127.0.0.1:29998".to_string(),
        kafka_brokers: "localhost:29999".to_string(),
        kafka_topic: "test".to_string(),
        js_token_secret: "test-secret".to_string(),
        captcha_site_key: "test-site-key".to_string(),
    });
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
