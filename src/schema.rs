use anyhow::Result;
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
    pub files: Vec<FileSpec>,
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
pub struct FileSpec {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    #[serde(default)]
    pub stdout_trunc: bool,
    #[serde(default)]
    pub stderr_trunc: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom_attestation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_path: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Green,
    Yellow,
    Red,
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
    pub fs: FsCapabilities,
    pub net: NetCapabilities,
    #[serde(default)]
    pub process: ProcessCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapabilities {
    pub default: AccessMode,
    #[serde(default)]
    pub allow: Vec<PathRule>,
    #[serde(default)]
    pub deny: Vec<PathRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRule {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetCapabilities {
    pub default: AccessMode,
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessCapabilities {
    #[serde(default = "default_true")]
    pub allow_fork: bool,
    #[serde(default = "default_max_processes")]
    pub max_processes: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub cpu_ms: u64,
    pub memory_mb: u64,
    pub wall_sec: u32,
    #[serde(default = "default_output_size")]
    pub output_size_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradingConfig {
    pub thresholds: Thresholds,
    pub static_scores: StaticScores,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    pub green: String,
    pub yellow: String,
    pub red: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticScores {
    pub etc_write: u32,
    pub unauthorized_tcp: u32,
    pub ssh_key_read: u32,
    pub fork_bomb: u32,
    pub large_output: u32,
    pub suspicious_pattern: u32,
}

fn default_policy_id() -> String {
    "default".to_string()
}

fn default_timeout() -> u32 {
    15
}

fn default_true() -> bool {
    true
}

fn default_max_processes() -> u32 {
    10
}

fn default_output_size() -> u64 {
    10
}

pub fn generate_run_id() -> String {
    format!("r_{}", Uuid::new_v4().simple().to_string().to_uppercase())
}

pub fn validate_request(request: &SpellRequest) -> Result<()> {
    if request.cmd.is_empty() {
        anyhow::bail!("Command cannot be empty");
    }
    if request.timeout_sec == 0 || request.timeout_sec > 60 {
        anyhow::bail!("Timeout must be between 1 and 60 seconds");
    }
    for file in &request.files {
        if !file.path.starts_with("/workspace/") {
            anyhow::bail!("File paths must start with /workspace/");
        }
    }
    Ok(())
}

pub fn validate_result(result: &SpellResult) -> Result<()> {
    if !result.run_id.starts_with("r_") || result.run_id.len() != 28 {
        anyhow::bail!("Invalid run_id format");
    }
    if result.risk_score > 100 {
        anyhow::bail!("Risk score must be between 0 and 100");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_run_id() {
        let id = generate_run_id();
        assert!(id.starts_with("r_"));
        assert_eq!(id.len(), 28);
    }

    #[test]
    fn test_validate_request() {
        let mut req = SpellRequest {
            cmd: "echo hello".to_string(),
            stdin: String::new(),
            env: HashMap::new(),
            files: vec![],
            policy_id: "default".to_string(),
            timeout_sec: 15,
            allow_net: vec![],
            allow_fs: vec![],
        };
        
        assert!(validate_request(&req).is_ok());
        
        req.cmd = "".to_string();
        assert!(validate_request(&req).is_err());
        
        req.cmd = "echo hello".to_string();
        req.timeout_sec = 0;
        assert!(validate_request(&req).is_err());
        
        req.timeout_sec = 61;
        assert!(validate_request(&req).is_err());
    }
}