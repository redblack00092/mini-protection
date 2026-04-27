use super::*;
use crate::pipeline::detector::{Action, DetectionResult, Detector};
use std::net::IpAddr;

struct AlwaysPass;
struct AlwaysBlock;
struct AlwaysChallenge;
struct AlwaysCaptcha;

impl Detector for AlwaysPass {
    fn detect(&self, _: &Packet) -> DetectionResult { DetectionResult::pass() }
    fn name(&self) -> &str { "always_pass" }
}
impl Detector for AlwaysBlock {
    fn detect(&self, _: &Packet) -> DetectionResult {
        DetectionResult::block("test block", 1.0)
    }
    fn name(&self) -> &str { "always_block" }
}
impl Detector for AlwaysChallenge {
    fn detect(&self, _: &Packet) -> DetectionResult {
        DetectionResult::challenge("test challenge", 0.5)
    }
    fn name(&self) -> &str { "always_challenge" }
}
impl Detector for AlwaysCaptcha {
    fn detect(&self, _: &Packet) -> DetectionResult {
        DetectionResult::captcha("test captcha", 0.8)
    }
    fn name(&self) -> &str { "always_captcha" }
}

fn test_packet() -> Packet {
    Packet::new(
        "1.2.3.4".parse::<IpAddr>().unwrap(),
        "10.0.0.1".parse::<IpAddr>().unwrap(),
    )
}

#[test]
fn passes_when_all_pass() {
    let p = Pipeline::new(vec![Box::new(AlwaysPass), Box::new(AlwaysPass)]);
    assert!(p.run(&test_packet()).is_pass());
}

#[test]
fn blocks_when_any_blocks() {
    let p = Pipeline::new(vec![
        Box::new(AlwaysPass),
        Box::new(AlwaysBlock),
        Box::new(AlwaysPass),
    ]);
    let result = p.run(&test_packet());
    assert!(result.is_block());
    assert_eq!(result.reason, "test block");
}

#[test]
fn block_early_exits_pipeline() {
    let p = Pipeline::new(vec![Box::new(AlwaysBlock), Box::new(AlwaysChallenge)]);
    let result = p.run(&test_packet());
    assert_eq!(result.action, Action::Block);
    assert_eq!(result.reason, "test block");
}

#[test]
fn returns_highest_priority_non_block() {
    let p = Pipeline::new(vec![
        Box::new(AlwaysChallenge),
        Box::new(AlwaysCaptcha),
        Box::new(AlwaysPass),
    ]);
    let result = p.run(&test_packet());
    assert_eq!(result.action, Action::Captcha);
}

#[test]
fn challenge_wins_over_pass() {
    let p = Pipeline::new(vec![Box::new(AlwaysPass), Box::new(AlwaysChallenge)]);
    let result = p.run(&test_packet());
    assert_eq!(result.action, Action::Challenge);
}

#[test]
fn empty_pipeline_passes() {
    let p = Pipeline::new(vec![]);
    assert!(p.run(&test_packet()).is_pass());
}

#[test]
fn detector_names_returns_all() {
    let p = Pipeline::new(vec![Box::new(AlwaysPass), Box::new(AlwaysBlock)]);
    let names = p.detector_names();
    assert_eq!(names, vec!["always_pass", "always_block"]);
}
