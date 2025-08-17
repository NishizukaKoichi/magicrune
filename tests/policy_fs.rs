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
