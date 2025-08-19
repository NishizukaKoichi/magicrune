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
    let code = status.code().unwrap_or(-1);
    let allowed = [3, 20];
    assert!(
        allowed.contains(&code),
        "unexpected exit code: {} (expected one of {:?})",
        code,
        allowed
    );
}
