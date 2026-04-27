/// WAF 설정 — 환경변수에서 로드한다. 설정되지 않은 항목은 기본값을 사용한다.
#[derive(Debug)]
pub struct Config {
    /// 수신 주소 (기본: "0.0.0.0:8080")
    pub listen_addr: String,
    /// 업스트림 백엔드 URL (기본: "http://localhost:8090")
    pub upstream_url: String,
    /// Kafka 브로커 주소 (기본: "localhost:9092")
    pub kafka_brokers: String,
    /// Kafka 토픽 이름 (기본: "mini-protection-events")
    pub kafka_topic: String,
    /// JS Challenge 쿠키 서명 시크릿 (기본: "change-me-in-production")
    pub js_token_secret: String,
    /// reCAPTCHA v2 사이트 키 (기본: "")
    pub captcha_site_key: String,
}

impl Config {
    /// 환경변수에서 설정을 로드한다.
    pub fn load() -> anyhow::Result<Self> {
        Ok(Self {
            listen_addr: std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            upstream_url: std::env::var("UPSTREAM_URL")
                .unwrap_or_else(|_| "http://localhost:8090".to_string()),
            kafka_brokers: std::env::var("KAFKA_BROKERS")
                .unwrap_or_else(|_| "localhost:9092".to_string()),
            kafka_topic: std::env::var("KAFKA_TOPIC")
                .unwrap_or_else(|_| "mini-protection-events".to_string()),
            js_token_secret: std::env::var("JS_TOKEN_SECRET")
                .unwrap_or_else(|_| "change-me-in-production".to_string()),
            captcha_site_key: std::env::var("CAPTCHA_SITE_KEY").unwrap_or_default(),
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/config.rs"]
mod tests;
