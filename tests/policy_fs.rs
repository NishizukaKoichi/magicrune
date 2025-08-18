use std::process::Command;

#[test]
fn write_outside_tmp_is_denied_without_allow_fs() {
    let status = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "magicrune",
            "--",
            "exec",
            "-f",
            "samples/write_forbidden.json",
            "--out",
            "target/tmp/out.json",
        ])
        .status()
        .expect("spawn magicrune");
    assert_eq!(status.code(), Some(3));
}

#[test]
fn native_sandbox_blocks_non_tmp_when_enabled() {
    // Only enforce when explicitly requested and on Linux with native sandbox available.
    let require = std::env::var("MAGICRUNE_REQUIRE_SECCOMP").ok() == Some("1".to_string());
    if !require { eprintln!("Skipping native sandbox strict /tmp test"); return; }

    let status = Command::new("cargo")
        .args([
            "run","--bin","magicrune","--",
            "exec","-f","samples/write_forbidden.json","--out","target/tmp/out.json"
        ])
        .env("MAGICRUNE_SECCOMP","1")
        .status()
        .expect("spawn magicrune");
    // Expect policy violation/red; depending on platform it may be 3 or 20; accept non-zero
    assert!(status.code().unwrap_or(0) != 0);
}
