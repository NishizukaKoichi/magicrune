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
    fn exec(&self, cmd: &str, _stdin: Option<&str>) -> Result<i32> {
        // Interpret `cmd` as a wasm file path if present (env can override)
        let wasm_path = std::env::var("MAGICRUNE_WASM_FILE").unwrap_or_else(|_| cmd.to_string());
        // Minimal WASI execution without preopened dirs; stdout/stderr inherited
        use wasmtime::{Engine, Linker, Module, Store};
        use wasmtime_wasi::sync::WasiCtxBuilder;

        let mut config = wasmtime::Config::new();
        // Enable fuel so we can bound CPU in the future
        let _ = config.consume_fuel(true);
        let engine = Engine::new(&config)?;
        let module = Module::from_file(&engine, &wasm_path)?;

        let wasi_ctx = WasiCtxBuilder::new()
            .inherit_stdout()
            .inherit_stderr()
            .build();

        let mut store = Store::new(&engine, wasi_ctx);

        let mut linker: Linker<wasmtime_wasi::WasiCtx> = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)?;
        let instance = linker.instantiate(&mut store, &module)?;
        let start = instance
            .get_func(&mut store, "_start")
            .ok_or_else(|| anyhow::anyhow!("_start not found"))?;
        // Call _start; WASI uses traps for exit; map to code 0 on success
        match start.call(&mut store, &[], &mut []) {
            Ok(()) => Ok(0),
            Err(e) => {
                // Best-effort: treat trap as non-zero
                eprintln!("wasi error: {e}");
                Ok(4)
            }
        }
    }
}
