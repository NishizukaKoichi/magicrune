use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SpellRequest {
    pub cmd: Option<String>,
    pub stdin: Option<String>,
    pub env: Option<serde_json::Map<String, serde_json::Value>>,
    pub files: Option<Vec<serde_json::Value>>,
    pub policy_id: Option<String>,
    pub timeout_sec: Option<u64>,
    pub allow_net: Option<Vec<String>>,
    pub allow_fs: Option<Vec<String>>,
    pub seed: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SpellResult {
    pub run_id: String,
    pub verdict: String,
    pub risk_score: u32,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout_trunc: bool,
    pub sbom_attestation: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GradingThresholds {
    pub green: String,
    pub yellow: String,
    pub red: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct PolicyDoc {
    pub version: u8,
    pub grading: Option<GradingCfg>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GradingCfg {
    pub thresholds: GradingThresholds,
}
