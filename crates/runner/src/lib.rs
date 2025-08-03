use anyhow::{Context, Result};
use magicrune_analyzer::Verdict;
use magicrune_audit::AuditEvent;
use magicrune_policy::{PolicyConfig, TrustLevel, NetworkMode};
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
use tracing::{debug, info, warn, error};

// Docker-first approach for cross-platform consistency
mod sandbox_docker;

// Legacy OS-specific implementations as fallback
#[cfg(target_os = "linux")]
mod sandbox_linux;
#[cfg(target_os = "macos")]
mod sandbox_macos;
#[cfg(target_os = "windows")]
mod sandbox_windows;

#[derive(Debug, Clone, PartialEq)]
pub enum RunMode {
    Direct,      // L0: 署名済み、即本番実行
    Local,       // L1: AI生成、ローカル実行
    Sandbox,     // L2: 外部ソース、サンドボックス強制
    Dryrun,      // テストモード（読み取り専用、ネットなし）
}

#[derive(Debug)]
pub struct RunContext {
    pub command: String,
    pub trust_level: TrustLevel,
    pub run_mode: RunMode,
    pub policy: PolicyConfig,
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub success: bool,
    pub output: String,
    pub verdict: Verdict,
    pub audit_events: Vec<AuditEvent>,
}

pub async fn execute(context: RunContext) -> Result<ExecutionResult> {
    info!(
        "Executing command with trust level {:?} in mode {:?}",
        context.trust_level, context.run_mode
    );

    match context.run_mode {
        RunMode::Direct => execute_direct(context).await,
        RunMode::Local => execute_local(context).await,
        RunMode::Sandbox => execute_sandbox(context).await,
        RunMode::Dryrun => execute_dryrun(context).await,
    }
}

async fn execute_direct(context: RunContext) -> Result<ExecutionResult> {
    info!("Direct execution mode (L0 - signed)");
    
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .arg("/C")
            .arg(&context.command)
            .output()
            .context("Failed to execute command")?
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(&context.command)
            .output()
            .context("Failed to execute command")?
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}\n{}", stdout, stderr);

    Ok(ExecutionResult {
        success: output.status.success(),
        output: combined_output,
        verdict: Verdict::Green,
        audit_events: vec![],
    })
}

async fn execute_local(context: RunContext) -> Result<ExecutionResult> {
    info!("Local execution mode (L1 - AI generated)");
    
    // Create audit context
    let mut audit_events = Vec::new();
    
    // Execute with basic monitoring
    let start_time = std::time::Instant::now();
    
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .arg("/C")
            .arg(&context.command)
            .output()
            .context("Failed to execute command")?
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(&context.command)
            .output()
            .context("Failed to execute command")?
    };

    let duration = start_time.elapsed();
    
    audit_events.push(AuditEvent::CommandExecution {
        command: context.command.clone(),
        exit_code: output.status.code().unwrap_or(-1),
        duration_ms: duration.as_millis() as u64,
    });

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}\n{}", stdout, stderr);

    // Basic analysis for local execution
    let analysis = magicrune_analyzer::analyze_behavior(&audit_events)?;

    Ok(ExecutionResult {
        success: output.status.success(),
        output: combined_output,
        verdict: analysis.verdict,
        audit_events,
    })
}

async fn execute_sandbox(context: RunContext) -> Result<ExecutionResult> {
    info!("Sandbox execution mode (L2 - external source)");
    
    let sandbox_config = SandboxConfig {
        network_mode: context.policy.default.network_mode.clone(),
        fs_write_root: context.policy.default.fs_write_root.clone(),
        secret_paths_deny: context.policy.default.secret_paths_deny.clone(),
        resource_limits: context.policy.sandbox.as_ref().and_then(|s| {
            Some(ResourceLimits {
                memory_mb: s.resource_limits.memory_mb,
                cpu_percent: s.resource_limits.cpu_percent,
                processes: s.resource_limits.processes,
            })
        }).unwrap_or_default(),
    };

    // Docker-first approach: Try Docker, fallback to OS-specific
    match sandbox_docker::execute_in_docker_sandbox(context.command.clone(), sandbox_config.clone()).await {
        Ok(result) => {
            info!("✅ Docker sandbox execution successful");
            return Ok(result);
        }
        Err(e) => {
            warn!("🐳 Docker unavailable, falling back to OS-specific sandbox: {}", e);
            
            // Fallback to OS-specific implementation
            #[cfg(target_os = "linux")]
            return sandbox_linux::execute_in_sandbox(context.command, sandbox_config).await;

            #[cfg(target_os = "macos")]
            return sandbox_macos::execute_in_sandbox(context.command, sandbox_config).await;

            #[cfg(target_os = "windows")]
            return sandbox_windows::execute_in_sandbox(context.command, sandbox_config).await;
        }
    }
}

async fn execute_dryrun(context: RunContext) -> Result<ExecutionResult> {
    info!("Dry-run mode - read-only sandbox with no network");
    
    let sandbox_config = SandboxConfig {
        network_mode: NetworkMode::None,
        fs_write_root: PathBuf::from("/tmp/sbx_dryrun"),
        secret_paths_deny: context.policy.default.secret_paths_deny.clone(),
        resource_limits: ResourceLimits {
            memory_mb: 256,  // Lower limits for dryrun
            cpu_percent: 25,
            processes: 8,
        },
    };

    // Docker-first approach for dryrun as well
    match sandbox_docker::execute_in_docker_sandbox(context.command.clone(), sandbox_config.clone()).await {
        Ok(result) => {
            info!("✅ Docker dryrun execution successful");
            return Ok(result);
        }
        Err(e) => {
            warn!("🐳 Docker unavailable for dryrun, falling back to OS-specific: {}", e);
            
            // Fallback to OS-specific implementation
            #[cfg(target_os = "linux")]
            return sandbox_linux::execute_in_sandbox(context.command, sandbox_config).await;

            #[cfg(target_os = "macos")]
            return sandbox_macos::execute_in_sandbox(context.command, sandbox_config).await;

            #[cfg(target_os = "windows")]
            return sandbox_windows::execute_in_sandbox(context.command, sandbox_config).await;
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub network_mode: NetworkMode,
    pub fs_write_root: PathBuf,
    pub secret_paths_deny: Vec<String>,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub memory_mb: u32,
    pub cpu_percent: u32,
    pub processes: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 512,
            cpu_percent: 50,
            processes: 32,
        }
    }
}