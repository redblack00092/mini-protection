use super::*;

#[test]
fn detection_event_serializes_to_json() {
    let event = DetectionEvent {
        timestamp: 1700000000,
        src_ip: "1.2.3.4".to_string(),
        uri: "/login".to_string(),
        detector: "ip_rate_limiter".to_string(),
        action: "Block".to_string(),
        reason: "IP rate limit exceeded".to_string(),
        confidence: 1.0,
        method: "POST".to_string(),
        http_version: "HTTP/1.1".to_string(),
        req_headers: vec![["user-agent".to_string(), "python-requests/2.31.0".to_string()]],
    };

    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"src_ip\":\"1.2.3.4\""));
    assert!(json.contains("\"action\":\"Block\""));
    assert!(json.contains("\"detector\":\"ip_rate_limiter\""));
    assert!(json.contains("\"confidence\":1.0"));
}

#[test]
fn detection_event_all_fields_present() {
    let event = DetectionEvent {
        timestamp: 0,
        src_ip: "::1".to_string(),
        uri: "/api/login".to_string(),
        detector: "credential_stuffing".to_string(),
        action: "Block".to_string(),
        reason: "distributed attack".to_string(),
        confidence: 0.95,
        method: "POST".to_string(),
        http_version: "HTTP/1.1".to_string(),
        req_headers: vec![],
    };

    let json = serde_json::to_string(&event).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["timestamp"], 0);
    assert_eq!(parsed["src_ip"], "::1");
    assert_eq!(parsed["uri"], "/api/login");
    assert_eq!(parsed["detector"], "credential_stuffing");
    assert_eq!(parsed["action"], "Block");
    assert_eq!(parsed["confidence"], 0.95);
}
