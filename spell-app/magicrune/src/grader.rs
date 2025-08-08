use crate::schema::{LogEntry, Policy, Verdict};
use anyhow::Result;
use std::collections::HashMap;

pub struct Grader {
    policy: Policy,
}

impl Grader {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    pub fn evaluate(&self, logs: &[LogEntry]) -> (Verdict, u32) {
        let mut risk_score = 0u32;
        
        for log in logs {
            risk_score += self.score_event(log);
        }
        
        let verdict = self.determine_verdict(risk_score);
        (verdict, risk_score)
    }

    fn score_event(&self, log: &LogEntry) -> u32 {
        match log.event.as_str() {
            "file_write" => {
                if let Some(path) = log.details.get("path").and_then(|v| v.as_str()) {
                    if path.starts_with("/etc/") {
                        return 50;
                    }
                    if path.contains(".ssh") {
                        return 40;
                    }
                    if path.starts_with("/tmp/") {
                        return 5;
                    }
                    return 15;
                }
                10
            }
            "file_read" => {
                if let Some(path) = log.details.get("path").and_then(|v| v.as_str()) {
                    if path.contains(".ssh") || path.contains("id_rsa") {
                        return 30;
                    }
                    if path.contains("/etc/passwd") || path.contains("/etc/shadow") {
                        return 25;
                    }
                }
                0
            }
            "network_connect" => {
                if let Some(blocked) = log.details.get("blocked").and_then(|v| v.as_bool()) {
                    if blocked {
                        return 40;
                    }
                }
                20
            }
            "process_spawn" => {
                if let Some(count) = log.details.get("fork_count").and_then(|v| v.as_u64()) {
                    if count > 100 {
                        return 25;
                    }
                    if count > 50 {
                        return 15;
                    }
                }
                5
            }
            "resource_limit" => {
                if let Some(resource) = log.details.get("resource").and_then(|v| v.as_str()) {
                    match resource {
                        "cpu" => 15,
                        "memory" => 20,
                        "pids" => 25,
                        _ => 10,
                    }
                } else {
                    10
                }
            }
            _ => 0,
        }
    }

    fn determine_verdict(&self, risk_score: u32) -> Verdict {
        let green_threshold = self.parse_threshold(&self.policy.grading.thresholds.green);
        let yellow_threshold = self.parse_threshold(&self.policy.grading.thresholds.yellow);
        let red_threshold = self.parse_threshold(&self.policy.grading.thresholds.red);
        
        if let (Some((_, green_max)), Some((yellow_min, yellow_max)), Some((red_min, _))) = 
            (green_threshold, yellow_threshold, red_threshold) {
            if risk_score <= green_max {
                Verdict::Green
            } else if risk_score >= yellow_min && risk_score <= yellow_max {
                Verdict::Yellow
            } else if risk_score >= red_min {
                Verdict::Red
            } else {
                Verdict::Yellow
            }
        } else {
            if risk_score <= 20 {
                Verdict::Green
            } else if risk_score <= 60 {
                Verdict::Yellow
            } else {
                Verdict::Red
            }
        }
    }

    fn parse_threshold(&self, threshold: &str) -> Option<(u32, u32)> {
        if threshold.contains("..=") {
            let parts: Vec<&str> = threshold.split("..=").collect();
            if parts.len() == 2 {
                let min = parts[0].parse::<u32>().ok()?;
                let max = parts[1].parse::<u32>().ok()?;
                return Some((min, max));
            }
        } else if threshold.starts_with("<=") {
            let value = threshold[2..].trim().parse::<u32>().ok()?;
            return Some((0, value));
        } else if threshold.starts_with(">=") {
            let value = threshold[2..].trim().parse::<u32>().ok()?;
            return Some((value, u32::MAX));
        }
        None
    }
}

pub struct RuneSage;

impl RuneSage {
    pub fn adjust_score(risk_score: u32, logs: &[LogEntry]) -> u32 {
        let mut adjusted = risk_score;
        
        let mut event_counts: HashMap<&str, usize> = HashMap::new();
        for log in logs {
            *event_counts.entry(&log.event).or_insert(0) += 1;
        }
        
        if event_counts.get("file_write").unwrap_or(&0) > &10 {
            adjusted = adjusted.saturating_add(10);
        }
        
        if event_counts.get("network_connect").unwrap_or(&0) > &5 {
            adjusted = adjusted.saturating_add(15);
        }
        
        let suspicious_patterns = [
            ("file_write", "network_connect"),
            ("file_read", "network_connect"),
            ("process_spawn", "file_write"),
        ];
        
        for (event1, event2) in &suspicious_patterns {
            if event_counts.contains_key(event1) && event_counts.contains_key(event2) {
                adjusted = adjusted.saturating_add(5);
            }
        }
        
        adjusted.min(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;
    use chrono::Utc;
    use serde_json::json;

    fn create_test_policy() -> Policy {
        Policy {
            version: 1,
            capabilities: Capabilities {
                fs: AccessPolicy {
                    default: AccessDefault::Deny,
                    allow: vec!["/tmp/**".to_string()],
                },
                net: AccessPolicy {
                    default: AccessDefault::Deny,
                    allow: vec![],
                },
            },
            limits: Limits {
                cpu_ms: 5000,
                memory_mb: 512,
                wall_sec: 15,
            },
            grading: GradingConfig {
                thresholds: Thresholds {
                    green: "<=20".to_string(),
                    yellow: "21..=60".to_string(),
                    red: ">=61".to_string(),
                },
            },
        }
    }

    #[test]
    fn test_grading() {
        let policy = create_test_policy();
        let grader = Grader::new(policy);
        
        let logs = vec![
            LogEntry {
                timestamp: Utc::now(),
                event: "file_write".to_string(),
                details: json!({ "path": "/tmp/test.txt" }),
            },
            LogEntry {
                timestamp: Utc::now(),
                event: "file_read".to_string(),
                details: json!({ "path": "/etc/passwd" }),
            },
        ];
        
        let (verdict, score) = grader.evaluate(&logs);
        assert_eq!(verdict, Verdict::Yellow);
        assert_eq!(score, 30);
    }

    #[test]
    fn test_ml_adjustment() {
        let logs = vec![
            LogEntry {
                timestamp: Utc::now(),
                event: "file_write".to_string(),
                details: json!({ "path": "/tmp/test.txt" }),
            },
            LogEntry {
                timestamp: Utc::now(),
                event: "network_connect".to_string(),
                details: json!({ "host": "example.com", "port": 443 }),
            },
        ];
        
        let base_score = 25;
        let adjusted = RuneSage::adjust_score(base_score, &logs);
        assert_eq!(adjusted, 30);
    }
}