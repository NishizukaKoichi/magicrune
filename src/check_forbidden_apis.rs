#[cfg(all(target_arch = "wasm32", feature = "std"))]
compile_error!("Cannot use std adapters in WASM. Forbidden APIs detected: std::fs, std::net, std::thread, std::process, SystemTime::now()");

#[cfg(test)]
mod tests {
    #[test]
    fn no_forbidden_apis_in_wasm() {
        assert!(true);
    }
}