use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::grader::{EventType, SandboxEvent};
use crate::schema::{FileSpec, Policy, SpellRequest};

const MAX_OUTPUT_SIZE: usize = 10 * 1024 * 1024; // 10MB

pub enum SandboxMode {
    Linux,
    Wasm,
}

pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: u64,
    pub events: Vec<SandboxEvent>,
}

pub struct Sandbox {
    mode: SandboxMode,
    policy: Policy,
}

impl Sandbox {
    pub fn new(policy: Policy) -> Result<Self> {
        let mode = if cfg!(target_os = "linux") {
            SandboxMode::Linux
        } else {
            SandboxMode::Wasm
        };
        
        Ok(Self { mode, policy })
    }

    pub async fn execute(&self, request: &SpellRequest) -> Result<SandboxResult> {
        match self.mode {
            SandboxMode::Linux => self.execute_linux(request).await,
            SandboxMode::Wasm => self.execute_wasm(request).await,
        }
    }

    async fn execute_linux(&self, request: &SpellRequest) -> Result<SandboxResult> {
        let workspace = TempDir::new()?;
        let workspace_path = workspace.path();
        
        self.prepare_workspace(workspace_path, &request.files)?;
        
        let (event_tx, mut event_rx) = mpsc::channel(100);
        let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let events_clone = events.clone();
        
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                events_clone.lock().await.push(event);
            }
        });

        let start = Instant::now();
        
        let mut cmd = Command::new("unshare");
        cmd.args(&[
            "--pid", "--net", "--mount", "--user", "--ipc", "--uts",
            "--map-root-user",
            "--",
            "/bin/sh", "-c", &request.cmd
        ]);
        
        cmd.current_dir(workspace_path);
        cmd.env_clear();
        cmd.envs(&request.env);
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        let timeout_duration = Duration::from_secs(request.timeout_sec as u64);
        let mut child = cmd.spawn()
            .context("Failed to spawn sandboxed process")?;
        
        if !request.stdin.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(request.stdin.as_bytes())?;
                stdin.flush()?;
                drop(stdin);
            }
        }
        
        let output_result: Result<std::process::Output> = match timeout(timeout_duration, 
            tokio::task::spawn_blocking(move || child.wait_with_output())
        ).await {
            Ok(Ok(Ok(output))) => Ok(output),
            Ok(Ok(Err(e))) => Err(e.into()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => {
                anyhow::bail!("Process timed out after {} seconds", request.timeout_sec);
            }
        };
        
        let duration_ms = start.elapsed().as_millis() as u64;
        let output = output_result?;
        
        let (stdout, stdout_truncated) = truncate_output(output.stdout);
        let (stderr, stderr_truncated) = truncate_output(output.stderr);
        
        let exit_code = output.status.code().unwrap_or(-1);
        
        if stdout.len() + stderr.len() > MAX_OUTPUT_SIZE {
            event_tx.send(SandboxEvent {
                event_type: EventType::OutputSize,
                details: (stdout.len() + stderr.len()).to_string(),
                timestamp_ms: duration_ms,
            }).await.ok();
        }
        
        drop(event_tx);
        
        let events_list = events.lock().await.clone();
        
        Ok(SandboxResult {
            exit_code,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            duration_ms,
            events: events_list,
        })
    }

    async fn execute_wasm(&self, request: &SpellRequest) -> Result<SandboxResult> {
        use wasmtime::*;
        use wasmtime_wasi::WasiCtxBuilder;
        
        let workspace = TempDir::new()?;
        let workspace_path = workspace.path();
        
        self.prepare_workspace(workspace_path, &request.files)?;
        
        let engine = Engine::default();
        let mut linker: Linker<wasmtime_wasi::WasiCtx> = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;
        
        let wasi = WasiCtxBuilder::new()
            .inherit_stdio()
            .inherit_args()?
            .build();
            
        let mut _store = Store::new(&engine, wasi);
        
        anyhow::bail!("WASM execution not fully implemented yet");
    }

    fn prepare_workspace(&self, workspace: &Path, files: &[FileSpec]) -> Result<()> {
        for file in files {
            let path = workspace.join(file.path.trim_start_matches('/'));
            
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            let content = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &file.content_b64
            ).context("Failed to decode base64 content")?;
            fs::write(&path, content)?;
        }
        
        Ok(())
    }
}

fn truncate_output(output: Vec<u8>) -> (String, bool) {
    let output_str = String::from_utf8_lossy(&output);
    
    if output_str.len() > MAX_OUTPUT_SIZE {
        let truncated = output_str.chars()
            .take(MAX_OUTPUT_SIZE)
            .collect::<String>();
        (truncated, true)
    } else {
        (output_str.into_owned(), false)
    }
}

pub async fn quarantine_output(run_id: &str, stdout: &str, stderr: &str) -> Result<String> {
    let quarantine_dir = PathBuf::from("quarantine");
    fs::create_dir_all(&quarantine_dir)?;
    
    let quarantine_file = quarantine_dir.join(format!("{}.txt", run_id));
    let mut file = fs::File::create(&quarantine_file)?;
    
    writeln!(file, "=== QUARANTINED OUTPUT ===")?;
    writeln!(file, "Run ID: {}", run_id)?;
    writeln!(file, "Timestamp: {}", chrono::Utc::now().to_rfc3339())?;
    writeln!(file, "\n=== STDOUT ===")?;
    write!(file, "{}", stdout)?;
    writeln!(file, "\n=== STDERR ===")?;
    write!(file, "{}", stderr)?;
    
    Ok(quarantine_file.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;

    fn test_policy() -> Policy {
        Policy {
            version: 1,
            capabilities: Capabilities {
                fs: FsCapabilities {
                    default: AccessMode::Deny,
                    allow: vec![
                        PathRule { path: "/tmp/**".to_string() },
                        PathRule { path: "/workspace/**".to_string() },
                    ],
                    deny: vec![],
                },
                net: NetCapabilities {
                    default: AccessMode::Deny,
                    allow: vec![],
                },
                process: ProcessCapabilities {
                    allow_fork: true,
                    max_processes: 10,
                },
            },
            limits: Limits {
                cpu_ms: 5000,
                memory_mb: 512,
                wall_sec: 15,
                output_size_mb: 10,
            },
            grading: GradingConfig {
                thresholds: Thresholds {
                    green: "<=20".to_string(),
                    yellow: "21..=60".to_string(),
                    red: ">=61".to_string(),
                },
                static_scores: StaticScores {
                    etc_write: 50,
                    unauthorized_tcp: 40,
                    ssh_key_read: 30,
                    fork_bomb: 25,
                    large_output: 15,
                    suspicious_pattern: 20,
                },
            },
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_simple_execution() -> Result<()> {
        let sandbox = Sandbox::new(test_policy())?;
        
        let request = SpellRequest {
            cmd: "echo hello".to_string(),
            stdin: String::new(),
            env: HashMap::new(),
            files: vec![],
            policy_id: "default".to_string(),
            timeout_sec: 5,
            allow_net: vec![],
            allow_fs: vec![],
        };
        
        let result = sandbox.execute(&request).await?;
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello"));
        
        Ok(())
    }
}