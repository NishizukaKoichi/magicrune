#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxKind {
    Wasi,
    Linux,
}

pub struct SandboxSpec {
    pub wall_sec: u64,
    pub cpu_ms: u64,
    pub memory_mb: u64,
}

pub struct SandboxOutcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl SandboxOutcome {
    pub fn empty() -> Self {
        Self {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }
}

/// Detect which sandbox to use at runtime.
/// Defaults to WASI unless running on Linux with the optional `linux_native` feature enabled.
/// If the env `MAGICRUNE_FORCE_WASM=1` is set, always selects WASI.
pub fn detect_sandbox() -> SandboxKind {
    if std::env::var("MAGICRUNE_FORCE_WASM").ok().as_deref() == Some("1") {
        return SandboxKind::Wasi;
    }

    #[cfg(all(target_os = "linux", feature = "linux_native"))]
    {
        return SandboxKind::Linux;
    }

    // Fallback
    SandboxKind::Wasi
}

// Placeholders for native/wasm sandbox backends (wired in CI later)
pub async fn exec_native(cmd: &str, stdin: &[u8], spec: &SandboxSpec) -> SandboxOutcome {
    #[cfg(all(target_os = "linux", feature = "linux_native"))]
    {
        if let Some(out) = linux_try_exec(cmd, stdin, spec).await {
            return out;
        }
    }
    simple_exec_with_timeout(cmd, stdin, spec).await
}

pub async fn exec_wasm(_wasm_bytes: &[u8], _spec: &SandboxSpec) -> SandboxOutcome {
    // Not executed in local bootstrap. Implemented in CI phase with proper deps.
    SandboxOutcome::empty()
}

// Optional Wasmtime wiring; compiled only when feature `wasm_exec` is enabled (CI).
#[cfg(feature = "wasm_exec")]
pub mod wasm_impl {
    use super::{SandboxOutcome, SandboxSpec};
    use wasmtime::{Config, Engine, Linker, Module, Store};
    use wasmtime_wasi::sync::WasiCtxBuilder;

    pub fn engine() -> Engine {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        Engine::new(&cfg).expect("engine")
    }

    pub async fn exec_bytes(wasm_bytes: &[u8], _spec: &SandboxSpec) -> SandboxOutcome {
        let engine = engine();
        let mut store = Store::new(&engine, WasiCtxBuilder::new().inherit_stdio().build());
        let module = match Module::from_binary(&engine, wasm_bytes) {
            Ok(m) => m,
            Err(_) => return SandboxOutcome::empty(),
        };
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |cx| cx).ok();
        let instance = match linker.instantiate(&mut store, &module) {
            Ok(i) => i,
            Err(_) => return SandboxOutcome::empty(),
        };
        // Try to call _start if present
        if let Ok(start) = instance.get_typed_func::<(), (), _>(&mut store, "_start") {
            let _ = start.call(&mut store, ());
        }
        SandboxOutcome::empty()
    }
}

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

async fn simple_exec_with_timeout(cmd: &str, stdin: &[u8], spec: &SandboxSpec) -> SandboxOutcome {
    let mut child = match Command::new("bash")
        .arg("-lc")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return SandboxOutcome::empty(),
    };
    if !stdin.is_empty() {
        use std::io::Write as _;
        if let Some(mut sin) = child.stdin.take() {
            let _ = sin.write_all(stdin);
        }
    }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(spec.wall_sec);
    loop {
        if let Ok(Some(_st)) = child.try_wait() {
            let out = match child.wait_with_output() {
                Ok(o) => o,
                Err(_) => return SandboxOutcome::empty(),
            };
            return SandboxOutcome {
                exit_code: out.status.code().unwrap_or(1),
                stdout: out.stdout,
                stderr: out.stderr,
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return SandboxOutcome {
                exit_code: 20,
                stdout: Vec::new(),
                stderr: b"timeout".to_vec(),
            };
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(all(target_os = "linux", feature = "linux_native"))]
async fn linux_try_exec(cmd: &str, stdin: &[u8], spec: &SandboxSpec) -> Option<SandboxOutcome> {
    use nix::sched::{unshare, CloneFlags};
    if unshare(
        CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS,
    )
    .is_err()
    {
        return None;
    }
    let out = simple_exec_with_timeout(cmd, stdin, spec).await;
    Some(out)
}
