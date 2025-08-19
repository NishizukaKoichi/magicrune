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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_spell_request_default() {
        let req = SpellRequest::default();
        assert!(req.cmd.is_none());
        assert!(req.stdin.is_none());
        assert!(req.env.is_none());
        assert!(req.files.is_none());
        assert!(req.policy_id.is_none());
        assert!(req.timeout_sec.is_none());
        assert!(req.allow_net.is_none());
        assert!(req.allow_fs.is_none());
        assert!(req.seed.is_none());
    }

    #[test]
    fn test_spell_request_serialization() {
        let req = SpellRequest {
            cmd: Some("echo hello".to_string()),
            stdin: Some("input".to_string()),
            env: Some(serde_json::Map::new()),
            files: Some(vec![]),
            policy_id: Some("default".to_string()),
            timeout_sec: Some(30),
            allow_net: Some(vec!["localhost".to_string()]),
            allow_fs: Some(vec!["/tmp".to_string()]),
            seed: Some(42),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: SpellRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.cmd, req.cmd);
        assert_eq!(deserialized.stdin, req.stdin);
        assert_eq!(deserialized.policy_id, req.policy_id);
        assert_eq!(deserialized.timeout_sec, req.timeout_sec);
        assert_eq!(deserialized.seed, req.seed);
    }

    #[test]
    fn test_spell_result_serialization() {
        let result = SpellResult {
            run_id: "test-123".to_string(),
            verdict: "safe".to_string(),
            risk_score: 10,
            exit_code: 0,
            duration_ms: 100,
            stdout_trunc: false,
            sbom_attestation: "attestation".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: SpellResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.run_id, result.run_id);
        assert_eq!(deserialized.verdict, result.verdict);
        assert_eq!(deserialized.risk_score, result.risk_score);
        assert_eq!(deserialized.exit_code, result.exit_code);
        assert_eq!(deserialized.duration_ms, result.duration_ms);
        assert_eq!(deserialized.stdout_trunc, result.stdout_trunc);
        assert_eq!(deserialized.sbom_attestation, result.sbom_attestation);
    }

    #[test]
    fn test_grading_thresholds_default() {
        let thresholds = GradingThresholds::default();
        assert_eq!(thresholds.green, "");
        assert_eq!(thresholds.yellow, "");
        assert_eq!(thresholds.red, "");
    }

    #[test]
    fn test_policy_doc_default() {
        let policy = PolicyDoc::default();
        assert_eq!(policy.version, 0);
        assert!(policy.grading.is_none());
    }

    #[test]
    fn test_grading_cfg_serialization() {
        let cfg = GradingCfg {
            thresholds: GradingThresholds {
                green: "0-30".to_string(),
                yellow: "31-70".to_string(),
                red: "71-100".to_string(),
            },
        };

        let json = serde_json::to_string(&cfg).unwrap();
        let deserialized: GradingCfg = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.thresholds.green, cfg.thresholds.green);
        assert_eq!(deserialized.thresholds.yellow, cfg.thresholds.yellow);
        assert_eq!(deserialized.thresholds.red, cfg.thresholds.red);
    }
}
