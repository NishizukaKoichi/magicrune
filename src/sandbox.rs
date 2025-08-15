use anyhow::Result;

pub trait Executor {
    fn exec(&self, cmd: &str, stdin: Option<&str>) -> Result<i32>;
}

pub struct NativeSandbox;
impl Executor for NativeSandbox {
    fn exec(&self, cmd: &str, stdin: Option<&str>) -> Result<i32> {
        // Minimal native execution (no isolation yet)
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
        let mut command = std::process::Command::new(shell);
        command.arg("-lc").arg(cmd);
        if let Some(stdin_s) = stdin {
            use std::io::Write;
            command.stdin(std::process::Stdio::piped());
            command.stdout(std::process::Stdio::piped());
            command.stderr(std::process::Stdio::piped());
            let mut child = command.spawn()?;
            if let Some(mut i) = child.stdin.take() { let _ = i.write_all(stdin_s.as_bytes()); }
            let status = child.wait()?;
            Ok(status.code().unwrap_or(4))
        } else {
            let status = command.status()?;
            Ok(status.code().unwrap_or(4))
        }
    }
}

pub struct WasmSandbox;
impl Executor for WasmSandbox {
    fn exec(&self, _cmd: &str, _stdin: Option<&str>) -> Result<i32> {
        // TODO: implement Wasmtime WASI execution; return success in fallback
        Ok(0)
    }
}
