use bootstrapped::sandbox::{detect_sandbox, SandboxKind};

#[test]
fn default_is_wasi_on_non_linux_or_when_feature_disabled() {
    #[cfg(not(all(target_os = "linux", feature = "linux_native")))]
    assert_eq!(detect_sandbox(), SandboxKind::Wasi);
}

#[test]
fn linux_native_is_selected_when_enabled_on_linux() {
    #[cfg(all(target_os = "linux", feature = "linux_native"))]
    assert_eq!(detect_sandbox(), SandboxKind::Linux);
}
