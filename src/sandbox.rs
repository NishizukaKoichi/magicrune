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
pub async fn exec_native(_cmd: &str, _stdin: &[u8], _spec: &SandboxSpec) -> SandboxOutcome {
    // Not executed in local bootstrap. Implemented in CI phase with proper deps.
    SandboxOutcome::empty()
}

pub async fn exec_wasm(_wasm_bytes: &[u8], _spec: &SandboxSpec) -> SandboxOutcome {
    // Not executed in local bootstrap. Implemented in CI phase with proper deps.
    SandboxOutcome::empty()
}

// Optional Wasmtime wiring; compiled only when feature `wasm_exec` is enabled (CI).
#[cfg(feature = "wasm_exec")]
pub mod wasm_impl {
    use super::{SandboxOutcome, SandboxSpec};
    use wasmtime::{Config, Engine};

    pub fn engine() -> Engine {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        Engine::new(&cfg).expect("engine")
    }

    pub async fn exec_bytes(_wasm_bytes: &[u8], _spec: &SandboxSpec) -> SandboxOutcome {
        let _engine = engine();
        SandboxOutcome::empty()
    }
}
