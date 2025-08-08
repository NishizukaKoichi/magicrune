use anyhow::{Context, Result};
use base64::Engine;
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{info, warn};
use wasmtime::{Config, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;

use crate::schema::{FileInput, LogEntry, Policy, SpellRequest};

pub enum SandboxBackend {
    Linux,
    Wasm,
}

pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub logs: Vec<LogEntry>,
}

pub struct Sandbox {
    backend: SandboxBackend,
    work_dir: TempDir,
}

impl Sandbox {
    pub async fn new() -> Result<Self> {
        let work_dir = TempDir::new()?;
        
        let backend = if cfg!(target_os = "linux") && Self::check_linux_capabilities() {
            SandboxBackend::Linux
        } else {
            info!("Linux sandbox not available, falling back to WASM");
            SandboxBackend::Wasm
        };
        
        Ok(Self { backend, work_dir })
    }

    pub async fn execute(
        &self,
        request: &SpellRequest,
        policy: &Policy,
    ) -> Result<SandboxResult> {
        self.prepare_filesystem(request).await?;
        
        match &self.backend {
            SandboxBackend::Linux => self.execute_linux(request, policy).await,
            SandboxBackend::Wasm => self.execute_wasm(request, policy).await,
        }
    }

    async fn prepare_filesystem(&self, request: &SpellRequest) -> Result<()> {
        for file in &request.files {
            let content = base64::engine::general_purpose::STANDARD
                .decode(&file.content_b64)
                .context("Failed to decode base64 file content")?;
            
            let target_path = self.work_dir.path().join(file.path.trim_start_matches('/'));
            
            if let Some(parent) = target_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            
            tokio::fs::write(&target_path, content).await?;
        }
        
        Ok(())
    }

    async fn execute_linux(
        &self,
        request: &SpellRequest,
        policy: &Policy,
    ) -> Result<SandboxResult> {
        let mut logs = Vec::new();
        
        let mut cmd = Command::new("unshare");
        cmd.args(&[
            "--user",
            "--pid",
            "--net",
            "--mount",
            "--ipc",
            "--uts",
            "--fork",
            "--map-root-user",
        ]);
        
        cmd.arg("sh");
        cmd.arg("-c");
        
        let sandbox_script = self.build_linux_sandbox_script(request, policy);
        cmd.arg(&sandbox_script);
        
        cmd.current_dir(self.work_dir.path());
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        for (key, value) in &request.env {
            cmd.env(key, value);
        }
        
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
        
        let mut child = cmd.spawn().context("Failed to spawn sandboxed process")?;
        
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(request.stdin.as_bytes()).await?;
            stdin.shutdown().await?;
        }
        
        let stdout = if let Some(mut reader) = child.stdout.take() {
            let mut buf = vec![0u8; 1024 * 1024];
            let mut output = String::new();
            while let Ok(n) = reader.read(&mut buf).await {
                if n == 0 { break; }
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
                if output.len() > 1024 * 1024 {
                    break;
                }
            }
            output
        } else {
            String::new()
        };

        let stderr = if let Some(mut reader) = child.stderr.take() {
            let mut buf = vec![0u8; 1024 * 1024];
            let mut output = String::new();
            while let Ok(n) = reader.read(&mut buf).await {
                if n == 0 { break; }
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
                if output.len() > 1024 * 1024 {
                    break;
                }
            }
            output
        } else {
            String::new()
        };
        
        let timeout_duration = Duration::from_secs(request.timeout_sec as u64);
        let result = timeout(timeout_duration, child.wait()).await;
        
        let exit_code = match result {
            Ok(Ok(status)) => status.code().unwrap_or(-1),
            Ok(Err(e)) => {
                warn!("Process error: {}", e);
                -2
            }
            Err(_) => {
                logs.push(LogEntry {
                    timestamp: chrono::Utc::now(),
                    event: "timeout".to_string(),
                    details: serde_json::json!({
                        "timeout_sec": request.timeout_sec
                    }),
                });
                let _ = child.kill().await;
                -3
            }
        };
        
        let stdout_truncated = stdout.len() >= 1024 * 1024;
        let stderr_truncated = stderr.len() >= 1024 * 1024;
        
        Ok(SandboxResult {
            exit_code,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            logs,
        })
    }

    async fn execute_wasm(
        &self,
        request: &SpellRequest,
        _policy: &Policy,
    ) -> Result<SandboxResult> {
        let logs = Vec::new();
        
        let config = Config::new();
        let engine = wasmtime::Engine::new(&config)?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;
        
        let wasi = WasiCtxBuilder::new()
            .inherit_stdio()
            .inherit_args()?
            .preopened_dir(
                wasmtime_wasi::Dir::open_ambient_dir(self.work_dir.path(), wasmtime_wasi::ambient_authority())?,
                "/tmp"
            )?
            .build();
        
        let mut store = Store::new(&engine, wasi);
        
        let wasm_binary = self.compile_to_wasm(&request.cmd).await?;
        let module = Module::new(&engine, wasm_binary)?;
        
        linker.module(&mut store, "", &module)?;
        let instance = linker.instantiate(&mut store, &module)?;
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
        
        let timeout_duration = Duration::from_secs(request.timeout_sec as u64);
        let result = timeout(timeout_duration, async {
            start.call(&mut store, ()).map_err(|e| anyhow::anyhow!("WASM execution failed: {}", e))
        }).await;
        
        let exit_code = match result {
            Ok(Ok(_)) => 0,
            Ok(Err(_)) => 1,
            Err(_) => -3,
        };
        
        Ok(SandboxResult {
            exit_code,
            stdout: "WASM execution completed".to_string(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            logs,
        })
    }

    fn build_linux_sandbox_script(&self, request: &SpellRequest, policy: &Policy) -> String {
        let mut script = String::new();
        
        script.push_str("#!/bin/sh\n");
        script.push_str("set -e\n");
        
        script.push_str("mount -t tmpfs tmpfs /tmp\n");
        script.push_str("mount -o ro,remount /\n");
        
        if let Ok(cgroup_path) = std::env::var("CGROUP_PATH") {
            script.push_str(&format!("echo $$ > {}/cgroup.procs\n", cgroup_path));
            script.push_str(&format!("echo {}000 > {}/cpu.max\n", policy.limits.cpu_ms, cgroup_path));
            script.push_str(&format!("echo {}M > {}/memory.max\n", policy.limits.memory_mb, cgroup_path));
            script.push_str(&format!("echo 100 > {}/pids.max\n", cgroup_path));
        }
        
        script.push_str(&format!("exec {}\n", request.cmd));
        
        script
    }

    async fn compile_to_wasm(&self, _cmd: &str) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("WASM compilation not implemented for arbitrary commands"))
    }

    fn check_linux_capabilities() -> bool {
        if !cfg!(target_os = "linux") {
            return false;
        }
        
        std::process::Command::new("unshare")
            .arg("--help")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;

    #[tokio::test]
    async fn test_sandbox_creation() {
        let sandbox = Sandbox::new().await.unwrap();
        assert!(matches!(sandbox.backend, SandboxBackend::Linux | SandboxBackend::Wasm));
    }

    #[tokio::test]
    async fn test_prepare_filesystem() {
        let sandbox = Sandbox::new().await.unwrap();
        
        let request = SpellRequest {
            cmd: "ls".to_string(),
            stdin: String::new(),
            env: HashMap::new(),
            files: vec![
                FileInput {
                    path: "test.txt".to_string(),
                    content_b64: base64::engine::general_purpose::STANDARD.encode("Hello, world!"),
                }
            ],
            policy_id: "default".to_string(),
            timeout_sec: 5,
            allow_net: vec![],
            allow_fs: vec![],
        };
        
        sandbox.prepare_filesystem(&request).await.unwrap();
        
        let test_file = sandbox.work_dir.path().join("test.txt");
        assert!(test_file.exists());
        
        let content = std::fs::read_to_string(test_file).unwrap();
        assert_eq!(content, "Hello, world!");
    }
}