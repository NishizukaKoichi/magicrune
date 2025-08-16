#[cfg(all(feature = "wasm_exec", not(target_env = "musl")))]
mod wasm_tests {
    #[test]
    fn wasm_engine_builds_via_crate() {
        // Use the crate's internal helper compiled behind feature `wasm_exec`
        let _engine = bootstrapped::sandbox::wasm_impl::engine();
    }
}
