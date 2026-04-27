use crate::packet::Packet;
use crate::pipeline::detector::{DetectionResult, Detector};
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

// ── 상수 ──────────────────────────────────────────────────────────────────

const WINDOW_SECS: u64 = 60;
const THRESHOLD: u32 = 30;

// ── 누적 위반 차단 시간 (초) ──────────────────────────────────────────────

fn block_until(violation_cnt: u32, now: u64) -> u64 {
    match violation_cnt {
        1 => now + 60,
        2 => now + 300,
        3 => now + 1800,
        _ => u64::MAX, // 영구 차단
    }
}

// ── IpEntry ───────────────────────────────────────────────────────────────

/// IP 하나에 대한 상태 레코드.
/// DashMap의 값으로 저장되며, shard 락 하에서만 접근된다.
pub struct IpEntry {
    pub ip: IpAddr,
    /// 현재 윈도우 내 요청 횟수
    pub count: u32,
    /// 현재 윈도우 시작 unix timestamp (초)
    pub window_start: u64,
    /// 누적 위반 횟수
    pub violation_cnt: u32,
    /// 현재 차단 상태
    pub blocked: bool,
    /// 차단 해제 unix timestamp (초)
    /// - 0: 차단 없음 (초기값)
    /// - u64::MAX: 영구 차단
    /// - 그 외: 해제 시각 (unix seconds)
    pub blocked_until: u64,
}

impl IpEntry {
    fn new(ip: IpAddr, now: u64) -> Self {
        Self {
            ip,
            count: 0,
            window_start: now,
            violation_cnt: 0,
            blocked: false,
            blocked_until: 0,
        }
    }
}

// ── IpRateLimiter ─────────────────────────────────────────────────────────

pub struct IpRateLimiter {
    entries: DashMap<IpAddr, IpEntry>,
}

impl IpRateLimiter {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Detector for IpRateLimiter {
    fn name(&self) -> &str {
        "ip_rate_limiter"
    }

    fn detect(&self, packet: &Packet) -> DetectionResult {
        let now = now_secs();
        let mut entry = self
            .entries
            .entry(packet.src_ip)
            .or_insert_with(|| IpEntry::new(packet.src_ip, now));

        // ── 1. 차단 상태 확인 ──────────────────────────────────────────────
        if entry.blocked {
            // 영구 차단
            if entry.blocked_until == u64::MAX {
                return DetectionResult::block("IP permanently blocked", 1.0);
            }

            // 차단 시간이 아직 남아 있음
            if now < entry.blocked_until {
                let n = entry.violation_cnt;
                return DetectionResult::block(
                    format!("IP rate limit exceeded. violations: {n}"),
                    1.0,
                );
            }

            // ── 3. 차단 해제 (시간 경과) ───────────────────────────────────
            entry.blocked = false;
            entry.blocked_until = 0;
            entry.count = 0;
            entry.window_start = now;
            entry.violation_cnt = 0;
        }

        // ── 4. Sliding Window 카운트 ───────────────────────────────────────
        // 윈도우가 만료되었으면 새 윈도우를 시작한다.
        if now.saturating_sub(entry.window_start) >= WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;

        // ── 5. 임계값 초과 → 차단 ─────────────────────────────────────────
        if entry.count > THRESHOLD {
            entry.violation_cnt += 1;
            entry.blocked = true;
            entry.blocked_until = block_until(entry.violation_cnt, now);

            let n = entry.violation_cnt;
            return DetectionResult::block(
                format!("IP rate limit exceeded. violations: {n}"),
                1.0,
            );
        }

        DetectionResult::pass()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/detectors/ip_rate_limiter.rs"]
mod tests;
