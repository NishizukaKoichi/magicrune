use anyhow::{Context, Result};
use magicrune_analyzer::Verdict;
use magicrune_audit::AuditEvent;
use std::process::Command;
use std::fs;
use tempfile::TempDir;
use tracing::{info, warn};

use crate::{ExecutionResult, SandboxConfig};

pub async fn execute_in_sandbox(command: String, config: SandboxConfig) -> Result<ExecutionResult> {
    info!("Setting up macOS sandbox environment");
    
    // Create temporary sandbox directory
    let sandbox_dir = TempDir::new().context("Failed to create sandbox directory")?;
    let sandbox_path = sandbox_dir.path();
    
    // Create sandbox profile
    let profile = create_sandbox_profile(&config, sandbox_path)?;
    let profile_path = sandbox_path.join("sandbox.sb");
    fs::write(&profile_path, profile)?;
    
    // Prepare command with sandbox-exec
    let mut sandbox_cmd = Command::new("sandbox-exec");
    sandbox_cmd.arg("-f").arg(&profile_path);
    sandbox_cmd.arg("sh");
    sandbox_cmd.arg("-c");
    sandbox_cmd.arg(&command);
    
    // Set environment restrictions
    sandbox_cmd.env_clear();
    sandbox_cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    sandbox_cmd.env("HOME", sandbox_path);
    sandbox_cmd.env("TMPDIR", sandbox_path.join("tmp"));
    
    // Execute
    let output = sandbox_cmd.output()
        .context("Failed to execute command in sandbox")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}\n{}", stdout, stderr);
    
    // Collect audit events
    let mut audit_events = vec![
        AuditEvent::SandboxExecution {
            profile: "macos_sandbox".to_string(),
            restrictions: vec![
                "network_isolated".to_string(),
                "fs_restricted".to_string(),
            ],
        },
        AuditEvent::CommandExecution {
            command: command.clone(),
            exit_code: output.status.code().unwrap_or(-1),
            duration_ms: 0, // TODO: measure actual duration
        },
    ];
    
    // Analyze behavior
    let analysis = magicrune_analyzer::analyze_behavior(&audit_events)?;
    
    Ok(ExecutionResult {
        success: output.status.success(),
        output: combined_output,
        verdict: analysis.verdict,
        audit_events,
    })
}

fn create_sandbox_profile(config: &SandboxConfig, sandbox_path: &std::path::Path) -> Result<String> {
    let network_rules = match &config.network_mode {
        magicrune_policy::NetworkMode::None => "(deny network*)",
        magicrune_policy::NetworkMode::Localhost => {
            "(allow network* (remote ip \"localhost:*\"))\n(allow network* (remote ip \"127.0.0.1:*\"))"
        }
        magicrune_policy::NetworkMode::Full => "(allow network*)",
    };
    
    let profile = format!(r#"
(version 1)

; Deny all by default
(deny default)

; Allow read access to system libraries and binaries
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "/System/Library")
    (subpath "/Library/Frameworks")
    (subpath "/dev/null")
    (subpath "/dev/zero")
    (subpath "/dev/random")
    (subpath "/dev/urandom"))

; Allow read/write in sandbox directory
(allow file*
    (subpath "{sandbox_path}"))

; Process execution
(allow process-exec
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "{sandbox_path}"))

(allow process-fork)

; Signals
(allow signal (target self))

; Sysctl
(allow sysctl-read)

; Network rules
{network_rules}

; Deny access to sensitive paths
(deny file*
    (subpath "/Users/*/Library/Keychains")
    (subpath "/Users/*/.ssh")
    (subpath "/Users/*/.aws")
    (subpath "/Users/*/.gnupg")
    (regex #".*\.env.*")
    (regex #".*credentials.*")
    (regex #".*secret.*"))

; System operations
(allow system-socket)
(allow mach-lookup
    (global-name "com.apple.system.logger"))
"#,
        sandbox_path = sandbox_path.display(),
        network_rules = network_rules
    );
    
    Ok(profile)
}