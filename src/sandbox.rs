use anyhow::Result;

pub trait Executor {
    fn exec(&self, cmd: &str, stdin: Option<&str>) -> Result<i32>;
}

pub struct NativeSandbox;
impl Executor for NativeSandbox {
    fn exec(&self, _cmd: &str, _stdin: Option<&str>) -> Result<i32> {
        // TODO: implement namespaces/cgroups/seccomp; stub returns success
        Ok(0)
    }
}

pub struct WasmSandbox;
impl Executor for WasmSandbox {
    fn exec(&self, _cmd: &str, _stdin: Option<&str>) -> Result<i32> {
        // TODO: implement Wasmtime WASI; stub returns success
        Ok(0)
    }
}
