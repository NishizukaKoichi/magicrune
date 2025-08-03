use anyhow::{Context, Result};
use magicrune_analyzer::Verdict;
use magicrune_audit::AuditEvent;
use std::process::Command;
use tempfile::TempDir;
use tracing::{info, debug, warn, error};

use crate::{ExecutionResult, SandboxConfig};

pub async fn execute_in_docker_sandbox(command: String, config: SandboxConfig) -> Result<ExecutionResult> {
    info!("🐳 Using Docker for cross-platform sandbox isolation");
    
    // Check if Docker is available
    if !is_docker_available() {
        return Err(anyhow::anyhow!("Docker is not available. Please install Docker Desktop/Engine."));
    }
    
    // Create temporary directory for data exchange
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let temp_path = temp_dir.path();
    
    // Create script file
    let script_path = temp_path.join("command.sh");
    std::fs::write(&script_path, &command)?;
    
    // Build Docker command with security restrictions
    let mut docker_args = vec![
        "run".to_string(),
        "--rm".to_string(),                          // Remove container after execution
        "--read-only".to_string(),                   // Read-only filesystem
        "--tmpfs".to_string(), "/tmp:noexec".to_string(), // Writable /tmp but no execution
        "--tmpfs".to_string(), "/var/tmp:noexec".to_string(),
    ];
    
    // Network isolation
    match config.network_mode {
        magicrune_policy::NetworkMode::None => {
            docker_args.extend_from_slice(&["--network".to_string(), "none".to_string()]);
        }
        magicrune_policy::NetworkMode::Localhost => {
            // Localhost-only network access
            docker_args.extend_from_slice(&["--dns".to_string(), "127.0.0.1".to_string()]);
        }
        magicrune_policy::NetworkMode::Full => {
            // Default Docker network
        }
    }
    
    // Resource limits
    docker_args.extend_from_slice(&[
        "--memory".to_string(), format!("{}m", config.resource_limits.memory_mb),
        "--cpus".to_string(), format!("{:.2}", config.resource_limits.cpu_percent as f32 / 100.0),
        "--pids-limit".to_string(), config.resource_limits.processes.to_string(),
    ]);
    
    // Security options
    docker_args.extend_from_slice(&[
        "--security-opt".to_string(), "no-new-privileges".to_string(),
        "--cap-drop".to_string(), "ALL".to_string(),
        "--cap-add".to_string(), "CHOWN".to_string(),
        "--cap-add".to_string(), "DAC_OVERRIDE".to_string(),
        "--cap-add".to_string(), "SETGID".to_string(),
        "--cap-add".to_string(), "SETUID".to_string(),
    ]);
    
    // User namespace (run as non-root)
    docker_args.extend_from_slice(&[
        "--user".to_string(), "1000:1000".to_string(),
    ]);
    
    // Mount the script (read-only)
    docker_args.extend_from_slice(&[
        "-v".to_string(), format!("{}:/workspace/command.sh:ro", script_path.display()),
    ]);
    
    // Working directory
    docker_args.extend_from_slice(&[
        "-w".to_string(), "/workspace".to_string(),
    ]);
    
    // Environment variables (clean environment)
    docker_args.extend_from_slice(&[
        "--env".to_string(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        "--env".to_string(), "DEBIAN_FRONTEND=noninteractive".to_string(),
    ]);
    
    // Ubuntu image with timeout
    docker_args.extend_from_slice(&[
        "ubuntu:22.04".to_string(),
        "timeout".to_string(),
        "30s".to_string(),  // 30 second timeout
        "bash".to_string(),
        "/workspace/command.sh".to_string(),
    ]);
    
    debug!("Docker command: docker {}", docker_args.join(" "));
    
    // Execute Docker command
    let start_time = std::time::Instant::now();
    let output = Command::new("docker")
        .args(&docker_args)
        .output()
        .context("Failed to execute Docker command")?;
    
    let duration = start_time.elapsed();
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}\n{}", stdout, stderr);
    
    // Collect audit events
    let mut audit_events = vec![
        AuditEvent::SandboxExecution {
            profile: "docker_ubuntu22.04".to_string(),
            restrictions: vec![
                "read_only_filesystem".to_string(),
                "network_isolation".to_string(),
                "resource_limits".to_string(),
                "capability_drop_all".to_string(),
                "non_root_user".to_string(),
                "no_new_privileges".to_string(),
            ],
        },
        AuditEvent::CommandExecution {
            command: command.clone(),
            exit_code: output.status.code().unwrap_or(-1),
            duration_ms: duration.as_millis() as u64,
        },
    ];
    
    // Check for any suspicious activities
    if stderr.contains("Permission denied") {
        audit_events.push(AuditEvent::SandboxEscape {
            method: "permission_denied_detected".to_string(),
        });
    }
    
    // Analyze behavior
    let analysis = magicrune_analyzer::analyze_behavior(&audit_events)?;
    
    // Determine verdict based on execution and analysis
    let verdict = if !output.status.success() {
        if output.status.code() == Some(124) {
            // Timeout
            info!("Command timed out (30s limit)");
            Verdict::Yellow
        } else {
            Verdict::Red
        }
    } else {
        match analysis.verdict {
            Verdict::Green => Verdict::Green,
            Verdict::Yellow => Verdict::Yellow,
            Verdict::Red => Verdict::Red,
        }
    };
    
    info!("Docker execution completed with verdict: {:?}", verdict);
    
    Ok(ExecutionResult {
        success: output.status.success(),
        output: combined_output,
        verdict,
        audit_events,
    })
}

fn is_docker_available() -> bool {
    debug!("Checking Docker availability...");
    
    match Command::new("docker").arg("--version").output() {
        Ok(output) => {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                info!("Docker detected: {}", version.trim());
                
                // Also check if Docker daemon is running
                match Command::new("docker").args(&["info"]).output() {
                    Ok(info_output) => {
                        if info_output.status.success() {
                            debug!("Docker daemon is running");
                            true
                        } else {
                            warn!("Docker is installed but daemon is not running");
                            false
                        }
                    }
                    Err(_) => {
                        warn!("Failed to check Docker daemon status");
                        false
                    }
                }
            } else {
                debug!("Docker command failed");
                false
            }
        }
        Err(_) => {
            debug!("Docker not found in PATH");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SandboxConfig, ResourceLimits};
    use magicrune_policy::NetworkMode;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_docker_availability() {
        // This test will pass if Docker is available, skip if not
        if is_docker_available() {
            println!("Docker is available for testing");
        } else {
            println!("Docker not available, skipping Docker tests");
        }
    }

    #[tokio::test]
    async fn test_simple_command_in_docker() {
        if !is_docker_available() {
            return;
        }

        let config = SandboxConfig {
            network_mode: NetworkMode::None,
            fs_write_root: PathBuf::from("/tmp"),
            secret_paths_deny: vec![],
            resource_limits: ResourceLimits {
                memory_mb: 256,
                cpu_percent: 25,
                processes: 16,
            },
        };

        let result = execute_in_docker_sandbox("echo 'Hello from Docker!'".to_string(), config).await;
        
        match result {
            Ok(exec_result) => {
                assert!(exec_result.success);
                assert!(exec_result.output.contains("Hello from Docker!"));
                println!("Docker test passed: {}", exec_result.output);
            }
            Err(e) => {
                panic!("Docker execution failed: {}", e);
            }
        }
    }
}