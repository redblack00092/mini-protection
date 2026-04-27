use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use serde::Serialize;
use std::time::Duration;

// ── DetectionEvent ────────────────────────────────────────────────────────

/// Kafka로 전송되는 탐지 이벤트.
/// Block / Challenge / Captcha 액션만 전송 (Pass는 제외)
#[derive(Debug, Serialize)]
pub struct DetectionEvent {
    /// Unix timestamp (초)
    pub timestamp: u64,
    /// 클라이언트 IP
    pub src_ip: String,
    /// 요청 URI
    pub uri: String,
    /// 탐지한 Detector 이름
    pub detector: String,
    /// 액션 (Block / Challenge / Captcha)
    pub action: String,
    /// 탐지 이유
    pub reason: String,
    /// 신뢰도 0.0 ~ 1.0
    pub confidence: f32,
}

// ── KafkaProducer ─────────────────────────────────────────────────────────

/// rdkafka FutureProducer 래퍼.
/// 탐지 이벤트를 JSON으로 직렬화하여 Kafka 토픽으로 전송한다.
pub struct KafkaProducer {
    producer: FutureProducer,
    topic: String,
}

impl KafkaProducer {
    /// Kafka 브로커 주소와 토픽 이름으로 프로듀서를 생성한다.
    pub fn new(brokers: &str, topic: &str) -> anyhow::Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "5000")
            .set("queue.buffering.max.ms", "100")
            .set("compression.type", "lz4")
            .create()?;

        Ok(Self {
            producer,
            topic: topic.to_string(),
        })
    }

    /// 탐지 이벤트를 Kafka로 비동기 전송한다.
    /// src_ip를 파티션 키로 사용하여 동일 IP의 이벤트가 같은 파티션으로 전송된다.
    pub async fn send(&self, event: &DetectionEvent) -> anyhow::Result<()> {
        let payload = serde_json::to_string(event)?;
        let key = event.src_ip.as_str();

        self.producer
            .send(
                FutureRecord::to(&self.topic)
                    .payload(payload.as_bytes())
                    .key(key),
                Timeout::After(Duration::from_secs(5)),
            )
            .await
            .map_err(|(err, _)| anyhow::anyhow!("kafka send error: {err}"))?;

        tracing::debug!(
            topic = %self.topic,
            src_ip = %event.src_ip,
            action = %event.action,
            "kafka event sent"
        );

        Ok(())
    }

    /// 토픽 이름 반환
    pub fn topic(&self) -> &str {
        &self.topic
    }
}

#[cfg(test)]
#[path = "../../tests/unit/kafka.rs"]
mod tests;
