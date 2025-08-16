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
        Self { exit_code: 0, stdout: Vec::new(), stderr: Vec::new() }
    }
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

