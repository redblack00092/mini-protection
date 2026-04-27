use super::*;

#[test]
fn load_returns_ok() {
    assert!(Config::load().is_ok());
}

#[test]
fn required_fields_are_non_empty() {
    let cfg = Config::load().unwrap();
    assert!(!cfg.listen_addr.is_empty());
    assert!(!cfg.upstream_url.is_empty());
    assert!(!cfg.kafka_brokers.is_empty());
    assert!(!cfg.kafka_topic.is_empty());
    assert!(!cfg.js_token_secret.is_empty());
    // captcha_site_key는 비어있을 수 있음
}
