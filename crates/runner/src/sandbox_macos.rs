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
    
    // Check if sandbox-exec is available
    if !std::path::Path::new("/usr/bin/sandbox-exec").exists() {
        // Fallback to basic isolation if sandbox-exec is not available
        return execute_with_basic_isolation(command, config).await;
    }
    
    // Create temporary sandbox directory
    let sandbox_dir = TempDir::new().context("Failed to create sandbox directory")?;
    let sandbox_path = sandbox_dir.path();
    
    // Create necessary directories
    fs::create_dir_all(sandbox_path.join("tmp"))?;
    fs::create_dir_all(sandbox_path.join("work"))?;
    
    // Create sandbox profile
    let profile = create_sandbox_profile(&config, sandbox_path)?;
    let profile_path = sandbox_path.join("sandbox.sb");
    fs::write(&profile_path, profile)?;
    
    // Prepare command with sandbox-exec
    let start_time = std::time::Instant::now();
    let mut sandbox_cmd = Command::new("sandbox-exec");
    sandbox_cmd.arg("-f").arg(&profile_path);
    sandbox_cmd.arg("sh");
    sandbox_cmd.arg("-c");
    sandbox_cmd.arg(&command);
    
    // Set working directory to sandbox
    sandbox_cmd.current_dir(sandbox_path.join("work"));
    
    // Set environment restrictions
    sandbox_cmd.env_clear();
    sandbox_cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    sandbox_cmd.env("HOME", sandbox_path);
    sandbox_cmd.env("TMPDIR", sandbox_path.join("tmp"));
    sandbox_cmd.env("PWD", sandbox_path.join("work"));
    
    // Execute
    let output = sandbox_cmd.output()
        .context("Failed to execute command in sandbox")?;
    
    let duration = start_time.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = if stderr.is_empty() {
        stdout.to_string()
    } else if stdout.is_empty() {
        stderr.to_string()
    } else {
        format!("STDOUT:\n{}\n\nSTDERR:\n{}", stdout, stderr)
    };
    
    // Collect audit events
    let mut audit_events = vec![
        AuditEvent::SandboxExecution {
            profile: "macos_sandbox".to_string(),
            restrictions: vec![
                format!("network_{}", match config.network_mode {
                    magicrune_policy::NetworkMode::None => "blocked",
                    magicrune_policy::NetworkMode::Localhost => "localhost_only",
                    magicrune_policy::NetworkMode::Full => "allowed",
                }),
                "fs_restricted".to_string(),
                "temp_directory_isolated".to_string(),
            ],
        },
        AuditEvent::CommandExecution {
            command: command.clone(),
            exit_code: output.status.code().unwrap_or(-1),
            duration_ms: duration.as_millis() as u64,
        },
    ];
    
    // Check for file operations in sandbox
    if sandbox_path.join("work").read_dir()?.count() > 0 {
        audit_events.push(AuditEvent::FileDelete {
            path: sandbox_path.join("work").display().to_string(),
        });
    }
    
    // Analyze behavior
    let analysis = magicrune_analyzer::analyze_behavior(&audit_events)?;
    
    Ok(ExecutionResult {
        success: output.status.success(),
        output: combined_output,
        verdict: analysis.verdict,
        audit_events,
    })
}

// Fallback for systems without sandbox-exec
async fn execute_with_basic_isolation(command: String, _config: SandboxConfig) -> Result<ExecutionResult> {
    info!("Executing with basic isolation (sandbox-exec not available)");
    
    let start_time = std::time::Instant::now();
    let mut cmd = Command::new("sh");
    cmd.arg("-c");
    cmd.arg(&command);
    
    // Basic environment isolation
    cmd.env_remove("SSH_AUTH_SOCK");
    cmd.env_remove("AWS_ACCESS_KEY_ID");
    cmd.env_remove("AWS_SECRET_ACCESS_KEY");
    
    let output = cmd.output()
        .context("Failed to execute command")?;
    
    let duration = start_time.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = if stderr.is_empty() {
        stdout.to_string()
    } else if stdout.is_empty() {
        stderr.to_string()
    } else {
        format!("STDOUT:\n{}\n\nSTDERR:\n{}", stdout, stderr)
    };
    
    let audit_events = vec![
        AuditEvent::CommandExecution {
            command: command.clone(),
            exit_code: output.status.code().unwrap_or(-1),
            duration_ms: duration.as_millis() as u64,
        },
    ];
    
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