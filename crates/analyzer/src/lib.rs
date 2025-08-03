use anyhow::Result;
use magicrune_audit::AuditEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    Green,  // Safe to execute
    Yellow, // Requires human review
    Red,    // Blocked - security risk
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAnalysis {
    pub verdict: Verdict,
    pub risk_score: u32,
    pub behaviors: Vec<DetectedBehavior>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedBehavior {
    pub category: String,
    pub description: String,
    pub severity: Severity,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub fn analyze_behavior(events: &[AuditEvent]) -> Result<BehaviorAnalysis> {
    let mut risk_score = 0u32;
    let mut behaviors = Vec::new();
    let mut recommendations = Vec::new();
    
    // Risk weights
    let risk_weights = get_default_risk_weights();
    
    for event in events {
        match event {
            AuditEvent::CommandExecution { command, exit_code, .. } => {
                if *exit_code != 0 {
                    behaviors.push(DetectedBehavior {
                        category: "execution_failure".to_string(),
                        description: format!("Command failed with exit code {}", exit_code),
                        severity: Severity::Low,
                        evidence: vec![command.clone()],
                    });
                    risk_score += 10;
                }
            }
            
            AuditEvent::FileRead { path, .. } => {
                if is_sensitive_path(path) {
                    behaviors.push(DetectedBehavior {
                        category: "secret_access".to_string(),
                        description: format!("Attempted to read sensitive file: {}", path),
                        severity: Severity::Critical,
                        evidence: vec![path.clone()],
                    });
                    risk_score += risk_weights.get("secret_access").unwrap_or(&100);
                }
            }
            
            AuditEvent::FileWrite { path, size } => {
                if is_sensitive_path(path) {
                    behaviors.push(DetectedBehavior {
                        category: "secret_modification".to_string(),
                        description: format!("Attempted to modify sensitive file: {}", path),
                        severity: Severity::Critical,
                        evidence: vec![path.clone()],
                    });
                    risk_score += 100;
                } else if *size > 100_000_000 { // 100MB
                    behaviors.push(DetectedBehavior {
                        category: "large_file_write".to_string(),
                        description: format!("Large file write detected: {} bytes", size),
                        severity: Severity::Medium,
                        evidence: vec![path.clone()],
                    });
                    risk_score += 30;
                }
            }
            
            AuditEvent::NetworkConnection { host, port, .. } => {
                if is_suspicious_host(host) {
                    behaviors.push(DetectedBehavior {
                        category: "suspicious_network".to_string(),
                        description: format!("Connection to suspicious host: {}:{}", host, port),
                        severity: Severity::High,
                        evidence: vec![format!("{}:{}", host, port)],
                    });
                    risk_score += risk_weights.get("network_external").unwrap_or(&40);
                }
            }
            
            AuditEvent::ProcessSpawn { command, .. } => {
                if is_dangerous_command(command) {
                    behaviors.push(DetectedBehavior {
                        category: "dangerous_command".to_string(),
                        description: format!("Dangerous command execution: {}", command),
                        severity: Severity::High,
                        evidence: vec![command.clone()],
                    });
                    risk_score += 50;
                }
            }
            
            AuditEvent::PrivilegeEscalation { method } => {
                behaviors.push(DetectedBehavior {
                    category: "privilege_escalation".to_string(),
                    description: format!("Privilege escalation attempt: {}", method),
                    severity: Severity::Critical,
                    evidence: vec![method.clone()],
                });
                risk_score += risk_weights.get("privilege_escalation").unwrap_or(&100);
            }
            
            AuditEvent::SandboxEscape { method } => {
                behaviors.push(DetectedBehavior {
                    category: "sandbox_escape".to_string(),
                    description: format!("Sandbox escape attempt: {}", method),
                    severity: Severity::Critical,
                    evidence: vec![method.clone()],
                });
                risk_score += 100;
            }
            
            AuditEvent::SandboxExecution { profile, restrictions } => {
                debug!("Sandbox execution with profile: {} and restrictions: {:?}", profile, restrictions);
            }
        }
    }
    
    // Determine verdict based on risk score and behaviors
    let verdict = determine_verdict(risk_score, &behaviors);
    
    // Add recommendations based on verdict
    match verdict {
        Verdict::Green => {
            if risk_score > 0 {
                recommendations.push("Code executed safely but showed minor suspicious behavior".to_string());
            }
        }
        Verdict::Yellow => {
            recommendations.push("Manual review required before production use".to_string());
            recommendations.push("Consider running additional security scans".to_string());
        }
        Verdict::Red => {
            recommendations.push("DO NOT execute this code in production".to_string());
            recommendations.push("Code shows clear signs of malicious behavior".to_string());
        }
    }
    
    Ok(BehaviorAnalysis {
        verdict,
        risk_score,
        behaviors,
        recommendations,
    })
}

fn get_default_risk_weights() -> HashMap<&'static str, u32> {
    [
        ("secret_access", 100),
        ("privilege_escalation", 100),
        ("known_malicious", 100),
        ("binary_execution", 50),
        ("network_external", 40),
        ("file_write_many", 30),
        ("obfuscation", 60),
    ]
    .iter()
    .cloned()
    .collect()
}

fn determine_verdict(risk_score: u32, behaviors: &[DetectedBehavior]) -> Verdict {
    // Check for any critical behaviors
    if behaviors.iter().any(|b| b.severity == Severity::Critical) {
        return Verdict::Red;
    }
    
    // Risk score thresholds
    if risk_score >= 80 {
        Verdict::Red
    } else if risk_score >= 30 {
        Verdict::Yellow
    } else {
        Verdict::Green
    }
}

fn is_sensitive_path(path: &str) -> bool {
    let sensitive_patterns = vec![
        ".ssh", ".aws", ".gnupg", ".docker",
        "credentials", "secret", "private",
        ".env", "config.json", "settings.json",
        "/etc/passwd", "/etc/shadow",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        ".pem", ".key", ".pfx", ".p12",
    ];
    
    sensitive_patterns.iter().any(|pattern| path.contains(pattern))
}

fn is_suspicious_host(host: &str) -> bool {
    // Check against known malicious domains
    let suspicious_domains = vec![
        "malware.com", "phishing.net", "exploit.org",
        // Add more known bad domains
    ];
    
    suspicious_domains.iter().any(|domain| host.contains(domain))
        || host.parse::<std::net::IpAddr>().is_ok() // Direct IP connections are suspicious
}

fn is_dangerous_command(command: &str) -> bool {
    let dangerous_patterns = vec![
        "rm -rf /", "dd if=/dev/zero", "mkfs",
        ":(){ :|:& };:", // Fork bomb
        "chmod 777", "iptables -F",
        "curl | sh", "wget | bash",
    ];
    
    dangerous_patterns.iter().any(|pattern| command.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_execution() {
        let events = vec![
            AuditEvent::CommandExecution {
                command: "echo 'Hello World'".to_string(),
                exit_code: 0,
                duration_ms: 10,
            },
        ];
        
        let analysis = analyze_behavior(&events).unwrap();
        assert_eq!(analysis.verdict, Verdict::Green);
        assert_eq!(analysis.risk_score, 0);
    }

    #[test]
    fn test_secret_access_detection() {
        let events = vec![
            AuditEvent::FileRead {
                path: "/home/user/.ssh/id_rsa".to_string(),
                size: 1024,
            },
        ];
        
        let analysis = analyze_behavior(&events).unwrap();
        assert_eq!(analysis.verdict, Verdict::Red);
        assert!(analysis.risk_score >= 80);
    }

    #[test]
    fn test_privilege_escalation() {
        let events = vec![
            AuditEvent::PrivilegeEscalation {
                method: "sudo without password".to_string(),
            },
        ];
        
        let analysis = analyze_behavior(&events).unwrap();
        assert_eq!(analysis.verdict, Verdict::Red);
    }
}