#[cfg(all(feature = "wasm_exec", not(target_env = "musl")))]
mod wasm_tests {
    #[test]
    fn wasmtime_engine_builds() {
        let mut cfg = wasmtime::Config::new();
        cfg.consume_fuel(true);
        let engine = wasmtime::Engine::new(&cfg).expect("engine");
        // Just ensure engine is constructed
        let _ = engine;
    }
}

