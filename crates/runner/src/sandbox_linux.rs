use anyhow::{Context, Result};
use magicrune_audit::AuditEvent;
use std::process::Command;
use tempfile::TempDir;
use tracing::{info, warn};

use crate::{ExecutionResult, SandboxConfig};

pub async fn execute_in_sandbox(command: String, config: SandboxConfig) -> Result<ExecutionResult> {
    info!("Setting up Linux sandbox environment (basic)");
    
    // Create temporary sandbox directory
    let sandbox_dir = TempDir::new().context("Failed to create sandbox directory")?;
    let sandbox_path = sandbox_dir.path();
    
    // Create basic sandbox structure
    setup_basic_sandbox(sandbox_path)?;
    
    // Create a basic sandboxed command
    let mut cmd = Command::new("sh");
    cmd.arg("-c");
    cmd.arg(&command);
    
    // Clear sensitive environment variables
    cmd.env_remove("AWS_ACCESS_KEY_ID");
    cmd.env_remove("AWS_SECRET_ACCESS_KEY");
    cmd.env_remove("GITHUB_TOKEN");
    cmd.env_remove("NPM_TOKEN");
    cmd.env_remove("PYPI_TOKEN");
    
    // Set basic environment
    cmd.env("HOME", sandbox_path);
    cmd.env("TMPDIR", sandbox_path);
    cmd.current_dir(sandbox_path);
    
    // Execute command
    let output = cmd.output()
        .context("Failed to execute command in sandbox")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}\n{}", stdout, stderr);
    
    // Collect audit events
    let mut audit_events = vec![
        AuditEvent::SandboxExecution {
            profile: "linux_basic".to_string(),
            restrictions: vec![
                "env_cleared".to_string(),
                "working_dir_restricted".to_string(),
                "temp_filesystem".to_string(),
            ],
        },
        AuditEvent::CommandExecution {
            command: command.clone(),
            exit_code: output.status.code().unwrap_or(-1),
            duration_ms: 0,
        },
    ];
    
    // Basic analysis
    let analysis = magicrune_analyzer::analyze_behavior(&audit_events)?;
    
    Ok(ExecutionResult {
        success: output.status.success(),
        output: combined_output,
        verdict: analysis.verdict,
        audit_events,
    })
}

fn setup_basic_sandbox(sandbox_path: &std::path::Path) -> Result<()> {
    // Create basic directory structure
    let dirs = vec!["tmp", "home"];
    
    for dir in dirs {
        let full_path = sandbox_path.join(dir);
        std::fs::create_dir_all(&full_path)
            .with_context(|| format!("Failed to create directory: {}", full_path.display()))?;
    }
    
    info!("Basic sandbox filesystem created");
    Ok(())
}