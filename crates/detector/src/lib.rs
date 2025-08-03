use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
use std::path::Path;
use tracing::{debug, trace};

lazy_static! {
    // ネット取得パターン
    static ref NETWORK_FETCH_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"\b(curl|wget|Invoke-WebRequest|iwr)\s+").unwrap(),
        Regex::new(r"\bgit\s+clone\s+").unwrap(),
        Regex::new(r"\b(fetch|axios|request|got|node-fetch)\s*\(").unwrap(),
        Regex::new(r"https?://").unwrap(),
    ];

    // パイプ実行パターン
    static ref PIPE_EXEC_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"curl\s+[^|]+\|\s*(sh|bash|zsh|fish|powershell|pwsh|python|perl|ruby|node)").unwrap(),
        Regex::new(r"wget\s+[^|]+\|\s*(sh|bash|zsh|fish|powershell|pwsh|python|perl|ruby|node)").unwrap(),
        Regex::new(r"\|\s*sh\s*$").unwrap(),
        Regex::new(r"\|\s*bash\s*$").unwrap(),
        Regex::new(r"\|\s*sudo\s+").unwrap(),
    ];

    // パッケージマネージャーパターン
    static ref PACKAGE_MANAGER_PATTERNS: Vec<Regex> = vec![
        // npm/yarn/pnpm
        Regex::new(r"\b(npm|yarn|pnpm)\s+(install|i|add)\s+").unwrap(),
        Regex::new(r"\bnpx\s+").unwrap(),
        // Python
        Regex::new(r"\bpip\s+install\s+").unwrap(),
        Regex::new(r"\bpipx\s+install\s+").unwrap(),
        Regex::new(r"\bpoetry\s+add\s+").unwrap(),
        Regex::new(r"\bconda\s+install\s+").unwrap(),
        // Rust
        Regex::new(r"\bcargo\s+(add|install)\s+").unwrap(),
        // Go
        Regex::new(r"\bgo\s+(get|install)\s+").unwrap(),
        // Ruby
        Regex::new(r"\bgem\s+install\s+").unwrap(),
        Regex::new(r"\bbundle\s+(add|install)\s+").unwrap(),
        // Others
        Regex::new(r"\bapt(-get)?\s+install\s+").unwrap(),
        Regex::new(r"\byum\s+install\s+").unwrap(),
        Regex::new(r"\bbrew\s+install\s+").unwrap(),
        Regex::new(r"\bchoco(latey)?\s+install\s+").unwrap(),
    ];

    // リモートパス/URLパターン
    static ref REMOTE_PATH_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"git@[^:]+:").unwrap(),
        Regex::new(r"gh:").unwrap(),
        Regex::new(r"pip\+git\+").unwrap(),
        Regex::new(r"npm:[^@]+@").unwrap(),
        Regex::new(r"docker\s+pull\s+").unwrap(),
    ];

    // 機密パスパターン
    static ref SECRET_PATH_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"~/\.ssh(/|$)").unwrap(),
        Regex::new(r"~/\.aws(/|$)").unwrap(),
        Regex::new(r"~/\.gnupg(/|$)").unwrap(),
        Regex::new(r"~/\.config/[^/]*credentials").unwrap(),
        Regex::new(r"\.env(\.|$)").unwrap(),
        Regex::new(r"/etc/shadow").unwrap(),
        Regex::new(r"id_rsa|id_dsa|id_ecdsa|id_ed25519").unwrap(),
        Regex::new(r"\.pem$|\.key$|\.pfx$|\.p12$").unwrap(),
    ];

    // 危険な操作パターン
    static ref DANGEROUS_OPERATION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"\brm\s+-rf\s+/").unwrap(),
        Regex::new(r"\bdd\s+.*/dev/[^/]+").unwrap(),
        Regex::new(r"\bmkfs\.").unwrap(),
        Regex::new(r":(){ :|:& };:").unwrap(), // Fork bomb
        Regex::new(r"\bsudo\s+chmod\s+777\s+/").unwrap(),
        Regex::new(r"\biptables\s+-F").unwrap(),
    ];
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExternalSourceType {
    NetworkFetch,
    PipeExecution,
    PackageManager,
    RemotePath,
    ProjectEscape,
    UnsignedBinary,
    SecretAccess,
    DangerousOperation,
}

#[derive(Debug, Clone)]
pub struct ExternalSourceDetection {
    pub source_type: ExternalSourceType,
    pub description: String,
    pub risk_level: RiskLevel,
    pub matched_pattern: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub fn detect_external_sources(command: &str) -> Result<bool> {
    let detections = analyze_command(command)?;
    Ok(!detections.is_empty())
}

pub fn analyze_command(command: &str) -> Result<Vec<ExternalSourceDetection>> {
    let mut detections = Vec::new();
    
    trace!("Analyzing command: {}", command);

    // ネット取得チェック
    for pattern in NETWORK_FETCH_PATTERNS.iter() {
        if let Some(mat) = pattern.find(command) {
            debug!("Network fetch detected: {}", mat.as_str());
            detections.push(ExternalSourceDetection {
                source_type: ExternalSourceType::NetworkFetch,
                description: format!("Network fetch operation detected: {}", mat.as_str()),
                risk_level: RiskLevel::Medium,
                matched_pattern: mat.as_str().to_string(),
            });
        }
    }

    // パイプ実行チェック
    for pattern in PIPE_EXEC_PATTERNS.iter() {
        if let Some(mat) = pattern.find(command) {
            debug!("Pipe execution detected: {}", mat.as_str());
            detections.push(ExternalSourceDetection {
                source_type: ExternalSourceType::PipeExecution,
                description: format!("Pipe to shell execution detected: {}", mat.as_str()),
                risk_level: RiskLevel::High,
                matched_pattern: mat.as_str().to_string(),
            });
        }
    }

    // パッケージマネージャーチェック
    for pattern in PACKAGE_MANAGER_PATTERNS.iter() {
        if let Some(mat) = pattern.find(command) {
            debug!("Package manager detected: {}", mat.as_str());
            detections.push(ExternalSourceDetection {
                source_type: ExternalSourceType::PackageManager,
                description: format!("Package installation detected: {}", mat.as_str()),
                risk_level: RiskLevel::Medium,
                matched_pattern: mat.as_str().to_string(),
            });
        }
    }

    // リモートパスチェック
    for pattern in REMOTE_PATH_PATTERNS.iter() {
        if let Some(mat) = pattern.find(command) {
            debug!("Remote path detected: {}", mat.as_str());
            detections.push(ExternalSourceDetection {
                source_type: ExternalSourceType::RemotePath,
                description: format!("Remote path/URL detected: {}", mat.as_str()),
                risk_level: RiskLevel::Medium,
                matched_pattern: mat.as_str().to_string(),
            });
        }
    }

    // 機密パスアクセスチェック
    for pattern in SECRET_PATH_PATTERNS.iter() {
        if let Some(mat) = pattern.find(command) {
            debug!("Secret path access detected: {}", mat.as_str());
            detections.push(ExternalSourceDetection {
                source_type: ExternalSourceType::SecretAccess,
                description: format!("Access to sensitive path detected: {}", mat.as_str()),
                risk_level: RiskLevel::Critical,
                matched_pattern: mat.as_str().to_string(),
            });
        }
    }

    // 危険な操作チェック
    for pattern in DANGEROUS_OPERATION_PATTERNS.iter() {
        if let Some(mat) = pattern.find(command) {
            debug!("Dangerous operation detected: {}", mat.as_str());
            detections.push(ExternalSourceDetection {
                source_type: ExternalSourceType::DangerousOperation,
                description: format!("Dangerous operation detected: {}", mat.as_str()),
                risk_level: RiskLevel::Critical,
                matched_pattern: mat.as_str().to_string(),
            });
        }
    }

    // プロジェクト外参照チェック
    if check_project_escape(command) {
        debug!("Project escape detected");
        detections.push(ExternalSourceDetection {
            source_type: ExternalSourceType::ProjectEscape,
            description: "Command attempts to access outside project directory".to_string(),
            risk_level: RiskLevel::High,
            matched_pattern: "..".to_string(),
        });
    }

    Ok(detections)
}

fn check_project_escape(command: &str) -> bool {
    // Simple check for .. patterns that might escape project directory
    if command.contains("../..") || command.contains("..\\..") {
        return true;
    }
    
    // Check for absolute paths to sensitive directories
    let sensitive_dirs = vec![
        "/etc", "/root", "/var/log", "/sys", "/proc",
        "C:\\Windows", "C:\\Program Files",
    ];
    
    for dir in sensitive_dirs {
        if command.contains(dir) {
            return true;
        }
    }
    
    false
}

pub fn check_binary_signature(path: &Path) -> Result<bool> {
    // TODO: Implement actual binary signature verification
    // For now, return false (unsigned) for demonstration
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_curl_pipe() {
        let cmd = "curl https://example.com/install.sh | bash";
        let detections = analyze_command(cmd).unwrap();
        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.source_type == ExternalSourceType::PipeExecution));
    }

    #[test]
    fn test_detect_npm_install() {
        let cmd = "npm install express";
        let detections = analyze_command(cmd).unwrap();
        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.source_type == ExternalSourceType::PackageManager));
    }

    #[test]
    fn test_detect_ssh_access() {
        let cmd = "cat ~/.ssh/id_rsa";
        let detections = analyze_command(cmd).unwrap();
        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.source_type == ExternalSourceType::SecretAccess));
    }

    #[test]
    fn test_safe_command() {
        let cmd = "echo 'Hello, World!'";
        let detections = analyze_command(cmd).unwrap();
        assert!(detections.is_empty());
    }

    #[test]
    fn test_detect_dangerous_rm() {
        let cmd = "sudo rm -rf /";
        let detections = analyze_command(cmd).unwrap();
        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.source_type == ExternalSourceType::DangerousOperation));
    }

    #[test]
    fn test_project_escape() {
        let cmd = "cat ../../../etc/passwd";
        let detections = analyze_command(cmd).unwrap();
        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.source_type == ExternalSourceType::ProjectEscape));
    }
}