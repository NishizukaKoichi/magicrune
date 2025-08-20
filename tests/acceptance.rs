use std::process::Command;

#[test]
#[ignore = "exec command output functionality not yet implemented"]
fn exec_ok_sample_returns_green_and_exit0() {
    // Run the magicrune binary with the ok sample and write to a temp file
    let out_path = "target/tmp/result.json";
    let _ = std::fs::create_dir_all("target/tmp");
    let status = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "magicrune",
            "--",
            "exec",
            "-f",
            "samples/ok.json",
            "--out",
            out_path,
        ])
        .status()
        .expect("failed to spawn cargo run");
    assert!(status.success(), "expected exit code 0 for ok sample");

    let data = std::fs::read_to_string(out_path).expect("result.json must exist");
    let v: serde_json::Value = serde_json::from_str(&data).expect("valid json");
    assert_eq!(v["verdict"], "green");
}
