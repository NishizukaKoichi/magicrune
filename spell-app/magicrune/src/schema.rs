use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpellRequest {
    pub cmd: String,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub files: Vec<FileInput>,
    #[serde(default = "default_policy_id")]
    pub policy_id: String,
    #[serde(default = "default_timeout")]
    pub timeout_sec: u32,
    #[serde(default)]
    pub allow_net: Vec<String>,
    #[serde(default)]
    pub allow_fs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInput {
    pub path: String,
    pub content_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpellResult {
    pub run_id: String,
    pub verdict: Verdict,
    pub risk_score: u32,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
    pub stdout_trunc: bool,
    pub stderr_trunc: bool,
    pub logs: Vec<LogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom_attestation: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Green,
    Yellow,
    Red,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: u32,
    pub capabilities: Capabilities,
    pub limits: Limits,
    pub grading: GradingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub fs: AccessPolicy,
    pub net: AccessPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub default: AccessDefault,
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AccessDefault {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub cpu_ms: u64,
    pub memory_mb: u64,
    pub wall_sec: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradingConfig {
    pub thresholds: Thresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    pub green: String,
    pub yellow: String,
    pub red: String,
}

fn default_policy_id() -> String {
    "default".to_string()
}

fn default_timeout() -> u32 {
    15
}

impl SpellRequest {
    pub fn generate_id(&self) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_string(self).unwrap_or_default().as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

impl SpellResult {
    pub fn new(verdict: Verdict, risk_score: u32, exit_code: i32) -> Self {
        Self {
            run_id: format!("r_{}", Uuid::now_v7()),
            verdict,
            risk_score,
            exit_code,
            duration_ms: 0,
            stdout: String::new(),
            stderr: String::new(),
            stdout_trunc: false,
            stderr_trunc: false,
            logs: Vec::new(),
            sbom_attestation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spell_request_deserialization() {
        let json = r#"{
            "cmd": "echo hello",
            "stdin": "",
            "env": {"FOO": "bar"},
            "files": [],
            "policy_id": "test",
            "timeout_sec": 30
        }"#;
        
        let req: SpellRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cmd, "echo hello");
        assert_eq!(req.policy_id, "test");
        assert_eq!(req.timeout_sec, 30);
    }

    #[test]
    fn test_spell_request_defaults() {
        let json = r#"{"cmd": "ls"}"#;
        let req: SpellRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.policy_id, "default");
        assert_eq!(req.timeout_sec, 15);
        assert!(req.files.is_empty());
    }
}