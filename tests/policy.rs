use std::process::Command;

#[test]
fn deny_net_sample_is_policy_violation() {
    // When command suggests network and allow_net is empty, exit code must be 3
    let status = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "magicrune",
            "--",
            "exec",
            "-f",
            "samples/deny_net.json",
            "--out",
            "target/tmp/out.json",
        ])
        .status()
        .expect("spawn magicrune");
    assert_eq!(status.code(), Some(3));
}
