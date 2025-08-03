use anyhow::{Context, Result};
use jsonschema::{Draft, JSONSchema};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy validation failed: {0}")]
    ValidationError(String),
    #[error("Policy file not found: {0}")]
    FileNotFound(PathBuf),
    #[error("Invalid policy format: {0}")]
    InvalidFormat(String),
    #[error("Forbidden policy change: {0}")]
    ForbiddenChange(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    L0, // 本人署名
    L1, // AI自動生成（外部依存なし）
    L2, // 外部ソース
    L3, // 既知悪性/危険操作
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    None,
    Localhost,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCodePolicy {
    EnforceSandbox,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AiGeneratedPolicy {
    AllowLocal,
    EnforceSandbox,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageTestConfig {
    pub enable: bool,
    pub egress_allowlist: Vec<String>,
    pub duration_sec: u32,
    pub dns_pin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultPolicy {
    pub external_code: ExternalCodePolicy,
    pub ai_pure_generated: AiGeneratedPolicy,
    pub network_mode: NetworkMode,
    pub package_test: PackageTestConfig,
    pub fs_write_root: PathBuf,
    pub secret_paths_deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub enable: bool,
    pub path: PathBuf,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_retention_days() -> u32 {
    90
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiReviewThreshold {
    pub green_auto_promote: bool,
    pub yellow_require_human: bool,
    pub red_block: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiReviewConfig {
    pub enable: bool,
    pub threshold: AiReviewThreshold,
    #[serde(default)]
    pub risk_weights: std::collections::HashMap<String, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    pub trusted_keys_path: PathBuf,
    pub require_signature_for_production: bool,
    #[serde(default)]
    pub allowed_algorithms: Vec<String>,
    #[serde(default = "default_verification_mode")]
    pub verification_mode: String,
}

fn default_verification_mode() -> String {
    "strict".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub path: PathBuf,
    #[serde(default = "default_cache_size")]
    pub max_size_mb: u32,
    #[serde(default = "default_cache_ttl")]
    pub ttl_days: u32,
}

fn default_cache_size() -> u32 {
    1024
}

fn default_cache_ttl() -> u32 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub memory_mb: u32,
    pub cpu_percent: u32,
    pub disk_mb: u32,
    pub processes: u32,
    pub open_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub namespaces: Vec<String>,
    pub capabilities_drop: String,
    pub seccomp_profile: String,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub version: u32,
    pub default: DefaultPolicy,
    pub audit: AuditConfig,
    pub ai_review: AiReviewConfig,
    pub signing: SigningConfig,
    #[serde(default)]
    pub cache: Option<CacheConfig>,
    #[serde(default)]
    pub sandbox: Option<SandboxConfig>,
}

impl PolicyConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(PolicyError::FileNotFound(path.to_path_buf()).into());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read policy file: {}", path.display()))?;

        Self::from_yaml(&content)
    }

    pub fn from_yaml(content: &str) -> Result<Self> {
        let config: Self = serde_yaml::from_str(content)
            .map_err(|e| PolicyError::InvalidFormat(e.to_string()))?;

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // 既定ポリシーの強制チェック
        if self.default.external_code != ExternalCodePolicy::EnforceSandbox {
            return Err(PolicyError::ForbiddenChange(
                "external_code must be enforce_sandbox".to_string(),
            )
            .into());
        }

        // スキーマ検証
        let schema_content = include_str!("../../../policy.schema.json");
        let schema = serde_json::from_str(schema_content)?;
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&schema)
            .map_err(|e| PolicyError::ValidationError(e.to_string()))?;

        let instance = serde_json::to_value(self)?;
        if let Err(errors) = compiled.validate(&instance) {
            let error_messages: Vec<String> = errors
                .map(|e| format!("{}: {}", e.instance_path, e))
                .collect();
            return Err(
                PolicyError::ValidationError(error_messages.join(", ")).into()
            );
        }

        Ok(())
    }

    pub fn default_config() -> Self {
        Self {
            version: 1,
            default: DefaultPolicy {
                external_code: ExternalCodePolicy::EnforceSandbox,
                ai_pure_generated: AiGeneratedPolicy::AllowLocal,
                network_mode: NetworkMode::None,
                package_test: PackageTestConfig {
                    enable: true,
                    egress_allowlist: vec![
                        "registry.npmjs.org:443".to_string(),
                        "pypi.org:443".to_string(),
                        "files.pythonhosted.org:443".to_string(),
                        "crates.io:443".to_string(),
                    ],
                    duration_sec: 30,
                    dns_pin: true,
                },
                fs_write_root: PathBuf::from("/tmp/sbx"),
                secret_paths_deny: vec![
                    "~/.ssh".to_string(),
                    "~/.aws".to_string(),
                    "~/.gnupg".to_string(),
                    "~/.config/*credentials*".to_string(),
                    "**/.env*".to_string(),
                ],
            },
            audit: AuditConfig {
                enable: true,
                path: PathBuf::from("~/.magicrune/audit"),
                retention_days: 90,
                log_level: "info".to_string(),
            },
            ai_review: AiReviewConfig {
                enable: true,
                threshold: AiReviewThreshold {
                    green_auto_promote: true,
                    yellow_require_human: true,
                    red_block: true,
                },
                risk_weights: [
                    ("secret_access", 100),
                    ("privilege_escalation", 100),
                    ("known_malicious", 100),
                    ("binary_execution", 50),
                    ("network_external", 40),
                    ("file_write_many", 30),
                    ("obfuscation", 60),
                ]
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
            },
            signing: SigningConfig {
                trusted_keys_path: PathBuf::from("~/.magicrune/trusted_keys"),
                require_signature_for_production: true,
                allowed_algorithms: vec![
                    "ssh-rsa".to_string(),
                    "ssh-ed25519".to_string(),
                    "gpg-rsa4096".to_string(),
                ],
                verification_mode: "strict".to_string(),
            },
            cache: Some(CacheConfig {
                path: PathBuf::from("~/.magicrune/cache"),
                max_size_mb: 1024,
                ttl_days: 30,
            }),
            sandbox: Some(SandboxConfig {
                namespaces: vec![
                    "pid".to_string(),
                    "net".to_string(),
                    "mnt".to_string(),
                    "user".to_string(),
                    "uts".to_string(),
                    "ipc".to_string(),
                ],
                capabilities_drop: "all".to_string(),
                seccomp_profile: "strict".to_string(),
                resource_limits: ResourceLimits {
                    memory_mb: 512,
                    cpu_percent: 50,
                    disk_mb: 100,
                    processes: 32,
                    open_files: 256,
                },
            }),
        }
    }

    pub fn get_policy_path() -> Result<PathBuf> {
        if let Ok(path) = std::env::var("MAGICRUNE_POLICY") {
            return Ok(PathBuf::from(path));
        }

        let home = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
        Ok(home.join(".magicrune").join("policy.yml"))
    }

    pub fn ensure_default_config() -> Result<()> {
        let policy_path = Self::get_policy_path()?;
        if !policy_path.exists() {
            if let Some(parent) = policy_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let default_config = Self::default_config();
            let yaml = serde_yaml::to_string(&default_config)?;
            std::fs::write(&policy_path, yaml)?;
            tracing::info!("Created default policy at: {}", policy_path.display());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config_valid() {
        let config = PolicyConfig::default_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_forbidden_external_code_change() {
        let mut config = PolicyConfig::default_config();
        // This should be rejected - external_code must be enforce_sandbox
        let yaml = r#"
version: 1
default:
  external_code: allow_local
  ai_pure_generated: allow_local
  network_mode: none
"#;
        assert!(PolicyConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn test_save_and_load_config() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("policy.yml");
        
        let config = PolicyConfig::default_config();
        let yaml = serde_yaml::to_string(&config)?;
        std::fs::write(&config_path, yaml)?;

        let loaded = PolicyConfig::load_from_file(&config_path)?;
        assert_eq!(loaded.version, config.version);
        assert_eq!(loaded.default.network_mode, config.default.network_mode);
        
        Ok(())
    }
}