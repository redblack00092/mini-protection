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
use crate::detectors::honeypot::{HoneypotDetector, HoneypotStore};
use crate::detectors::js_challenge::JsChallengeDetector;
use crate::kafka::{DetectionEvent, KafkaProducer};
use crate::packet::Packet;
use crate::pipeline::Pipeline;
use crate::pipeline::detector::Action;
use dashmap::DashMap;

// ── AppState ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    pipeline: Arc<Pipeline>,
    kafka: Arc<KafkaProducer>,
    cfg: Arc<config::Config>,
    js_detector: Arc<JsChallengeDetector>,
    captcha_detector: Arc<CaptchaDetector>,
    http_client: Client<HttpConnector, Full<Bytes>>,
    honeypot_caught: HoneypotStore,
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

// 사람 눈에 보이지 않는 허니팟 링크 — CSS로 완전히 숨겨져 있음.
const HONEYPOT_LINK: &str = concat!(
    r#"<a href="/__mini-protection/trap" "#,
    r#"style="display:none;position:absolute;left:-9999px" "#,
    r#"tabindex="-1" aria-hidden="true"> </a>"#,
);

/// HTML 응답의 `</body>` 직전에 허니팟 링크를 주입한다.
/// `</body>` 태그가 없으면 원본을 그대로 반환한다.
fn inject_honeypot_link(body: Bytes) -> Bytes {
    if let Ok(html) = std::str::from_utf8(&body) {
        if let Some(pos) = html.rfind("</body>") {
            let mut result = String::with_capacity(html.len() + HONEYPOT_LINK.len());
            result.push_str(&html[..pos]);
            result.push_str(HONEYPOT_LINK);
            result.push_str(&html[pos..]);
            return Bytes::from(result);
        }
    }
    body
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

const SENSITIVE_HEADERS: &[&str] = &[
    "cookie", "authorization", "x-api-key", "x-auth-token", "proxy-authorization",
];

fn send_kafka_event(
    state: &AppState,
    src_ip: IpAddr,
    uri: &str,
    reason: &str,
    confidence: f32,
    action: &'static str,
    packet: Option<&Packet>,
) {
    let (method, http_version, req_headers) = match packet {
        Some(pkt) => {
            let headers = pkt.headers.iter()
                .filter(|(name, _)| !SENSITIVE_HEADERS.contains(&name.as_str()))
                .map(|(name, value)| [name.clone(), value.clone()])
                .collect();
            (pkt.method.clone(), pkt.http_version.clone(), headers)
        }
        None => (String::new(), String::new(), vec![]),
    };

    let event = DetectionEvent {
        timestamp: now_secs(),
        src_ip: src_ip.to_string(),
        uri: uri.to_string(),
        detector: "pipeline".to_string(),
        action: action.to_string(),
        reason: reason.to_string(),
        confidence,
        method,
        http_version,
        req_headers,
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

    let honeypot_caught: HoneypotStore = Arc::new(DashMap::new());

    let pipeline = Arc::new(Pipeline::new(vec![
        Box::new(HoneypotDetector::new(Arc::clone(&honeypot_caught))),
        Box::new(detectors::ip_rate_limiter::IpRateLimiter::new()),
        Box::new(detectors::path_scanner::PathScannerDetector::new()),
        Box::new(detectors::ja3_fingerprint::Ja3FingerprintDetector::new()),
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
        honeypot_caught,
    };

    let app = Router::new()
        .route("/__mini-protection/health", get(health_handler))
        .route("/__mini-protection/js-challenge/verify", post(js_verify_handler))
        .route("/__mini-protection/captcha/verify", post(captcha_verify_handler))
        .route("/__mini-protection/trap", get(honeypot_trap_handler))
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

// ── Honeypot Trap ─────────────────────────────────────────────────────────

/// HTML 응답에 숨겨진 트랩 링크에 접근한 봇을 기록한다.
///
/// 사람 눈에는 보이지 않는 링크를 봇이 파싱해서 따라오면 해당 IP를 HoneypotStore에 기록.
/// 404를 반환해 스마트한 봇도 탐지 사실을 알아채기 어렵게 한다.
async fn honeypot_trap_handler(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let src_ip = extract_ip(&headers, peer);
    state.honeypot_caught.insert(src_ip, ());
    tracing::info!(ip = %src_ip, "HONEYPOT: bot trapped");
    send_kafka_event(&state, src_ip, "/__mini-protection/trap", "Honeypot trap accessed", 1.0, "Block", None);
    StatusCode::NOT_FOUND.into_response()
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
            tracing::info!(ip = %src_ip, uri = %packet.uri, reason = %result.reason, "BLOCK");
            send_kafka_event(&state, src_ip, &packet.uri, &result.reason, result.confidence, "Block", Some(&packet));
            block_response(&result.reason)
        }
        Action::Challenge => {
            tracing::info!(ip = %src_ip, uri = %packet.uri, reason = %result.reason, "CHALLENGE");
            send_kafka_event(&state, src_ip, &packet.uri, &result.reason, result.confidence, "Challenge", Some(&packet));
            js_challenge_response(&packet.uri)
        }
        Action::Captcha => {
            if state.cfg.captcha_site_key.is_empty() {
                proxy_upstream(&state, parts, body_bytes).await
            } else {
                tracing::info!(ip = %src_ip, uri = %packet.uri, reason = %result.reason, "CAPTCHA");
                send_kafka_event(&state, src_ip, &packet.uri, &result.reason, result.confidence, "Captcha", Some(&packet));
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

    if let Some(ja3) = parts.headers.get("x-ja3-fingerprint") {
        if let Ok(v) = ja3.to_str() {
            packet.ja3_fingerprint = Some(v.to_string());
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

    // HTML 응답에 허니팟 링크 주입
    let is_html = resp_parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/html"))
        .unwrap_or(false);

    let final_bytes = if is_html {
        let injected = inject_honeypot_link(resp_bytes);
        // Content-Length가 있으면 새 크기로 갱신
        if resp_parts.headers.contains_key(header::CONTENT_LENGTH) {
            if let Ok(v) = injected.len().to_string().parse() {
                resp_parts.headers.insert(header::CONTENT_LENGTH, v);
            }
        }
        injected
    } else {
        resp_bytes
    };

    Response::from_parts(resp_parts, axum::body::Body::from(final_bytes))
}

#[cfg(test)]
#[path = "../tests/unit/main_unit.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/integration/proxy.rs"]
mod integration_tests;

