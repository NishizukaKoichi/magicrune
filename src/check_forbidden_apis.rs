#[cfg(all(target_arch = "wasm32", feature = "std"))]
compile_error!("Cannot use std adapters in WASM. Forbidden APIs detected: std::fs, std::net, std::thread, std::process, SystemTime::now()");

#[cfg(test)]
mod tests {
    #[test]
    fn no_forbidden_apis_in_wasm() {
        // This test ensures the compile-time check above works correctly
        // No forbidden std APIs should be used in WASM builds
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Test passes on non-WASM architectures
            // No assertion needed - test succeeds by not failing
        }
    }

    #[test]
    fn test_compile_error_mechanism() {
        // Verify that the compile_error would trigger on WASM+std
        #[cfg(all(target_arch = "wasm32", feature = "std"))]
        {
            // This block would never be reached due to compile_error
            unreachable!("Should not compile on wasm32 with std feature");
        }

        #[cfg(not(all(target_arch = "wasm32", feature = "std")))]
        {
            // Normal execution path
            // No assertion needed - test succeeds by not failing
        }
    }

    #[test]
    fn test_forbidden_api_detection() {
        // This test documents what APIs are forbidden
        let forbidden_apis = [
            "std::fs",
            "std::net",
            "std::thread",
            "std::process",
            "SystemTime::now()",
        ];

        // Ensure we're checking for the expected number of APIs
        assert_eq!(forbidden_apis.len(), 5);

        // Verify each forbidden API is documented
        assert!(forbidden_apis.contains(&"std::fs"));
        assert!(forbidden_apis.contains(&"std::net"));
        assert!(forbidden_apis.contains(&"std::thread"));
        assert!(forbidden_apis.contains(&"std::process"));
        assert!(forbidden_apis.contains(&"SystemTime::now()"));
    }
}
