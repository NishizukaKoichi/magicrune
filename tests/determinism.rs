use std::process::Command;

#[test]
fn same_request_and_seed_yield_same_run_id() {
    let out1 = "target/tmp/det1.json";
    let out2 = "target/tmp/det2.json";
    let _ = std::fs::create_dir_all("target/tmp");

    let status1 = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "magicrune",
            "--",
            "exec",
            "-f",
            "samples/ok.json",
            "--seed",
            "42",
            "--out",
            out1,
        ])
        .status()
        .expect("spawn 1");
    assert!(status1.success());

    let status2 = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "magicrune",
            "--",
            "exec",
            "-f",
            "samples/ok.json",
            "--seed",
            "42",
            "--out",
            out2,
        ])
        .status()
        .expect("spawn 2");
    assert!(status2.success());

    let v1: serde_json::Value = serde_json::from_slice(&std::fs::read(out1).unwrap()).unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&std::fs::read(out2).unwrap()).unwrap();
    assert_eq!(v1["run_id"], v2["run_id"]);
}
