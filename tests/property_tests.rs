//! Property-based tests for MagicRune
//! These tests use proptest to generate random inputs and verify invariants

use proptest::prelude::*;
use std::fs;
use std::process::Command;

/// Generate valid JSON request with random values
fn arb_spell_request() -> impl Strategy<Value = serde_json::Value> {
    (
        // cmd: various command patterns
        prop_oneof![
            Just("echo test".to_string()),
            Just("ls /tmp".to_string()),
            Just("cat /tmp/test.txt".to_string()),
            "[a-zA-Z0-9 /._-]{1,100}",
        ],
        // stdin
        prop_oneof![Just("".to_string()), "[a-zA-Z0-9\n ]{0,100}",],
        // timeout_sec: 1-60
        1u64..=60u64,
        // allow_net: random hosts
        prop::collection::vec(
            prop_oneof![
                Just("localhost:8080".to_string()),
                Just("127.0.0.1:80".to_string()),
                Just("example.com:443".to_string()),
                "[a-z0-9.-]+:[0-9]{1,5}",
            ],
            0..3,
        ),
        // allow_fs: random paths
        prop::collection::vec(
            prop_oneof![
                Just("/tmp/**".to_string()),
                Just("/tmp/test".to_string()),
                "/tmp/[a-z0-9_-]{1,20}",
            ],
            0..3,
        ),
        // files to write
        prop::collection::vec(
            (
                prop_oneof![
                    Just("/tmp/test.txt".to_string()),
                    "/tmp/[a-z0-9_-]{1,20}.txt",
                ],
                prop_oneof![Just("".to_string()), "[a-zA-Z0-9+/=]{0,100}",],
            ),
            0..3,
        ),
    )
        .prop_map(|(cmd, stdin, timeout_sec, allow_net, allow_fs, files)| {
            serde_json::json!({
                "cmd": cmd,
                "stdin": stdin,
                "env": {},
                "files": files.into_iter().map(|(path, content_b64)| {
                    serde_json::json!({
                        "path": path,
                        "content_b64": content_b64
                    })
                }).collect::<Vec<_>>(),
                "policy_id": "default",
                "timeout_sec": timeout_sec,
                "allow_net": allow_net,
                "allow_fs": allow_fs
            })
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_valid_request_produces_valid_result(request in arb_spell_request()) {
        // Write request to temp file
        let _ = fs::create_dir_all("target/tmp");
        let req_path = format!("target/tmp/prop_req_{}.json", uuid::Uuid::new_v4());
        let out_path = format!("target/tmp/prop_out_{}.json", uuid::Uuid::new_v4());

        fs::write(&req_path, serde_json::to_string_pretty(&request).unwrap()).unwrap();

        // Run magicrune
        let status = Command::new("cargo")
            .args([
                "run",
                "--",
                "exec",
                "-f",
                &req_path,
                "--out",
                &out_path,
            ])
            .env("MAGICRUNE_FORCE_WASM", "1")
            .output()
            .expect("Failed to execute");

        // Should complete without panic
        prop_assert!(status.status.code().is_some(), "Process should not crash");

        // If successful, validate output
        if status.status.success() {
            let output = fs::read_to_string(&out_path).expect("Output file should exist");
            let result: serde_json::Value = serde_json::from_str(&output).expect("Valid JSON");

            // Verify required fields
            prop_assert!(result.get("run_id").is_some());
            prop_assert!(result.get("verdict").is_some());
            prop_assert!(result.get("risk_score").is_some());
            prop_assert!(result.get("exit_code").is_some());
            prop_assert!(result.get("duration_ms").is_some());

            // Verify verdict is valid
            let verdict = result["verdict"].as_str().unwrap();
            prop_assert!(["green", "yellow", "red"].contains(&verdict));

            // Verify risk score is reasonable
            let risk_score = result["risk_score"].as_u64().unwrap();
            prop_assert!(risk_score <= 100);
        }

        // Cleanup
        let _ = fs::remove_file(&req_path);
        let _ = fs::remove_file(&out_path);
    }

    #[test]
    fn prop_deterministic_run_id(
        request in arb_spell_request(),
        seed in 0u64..1000u64
    ) {
        let _ = fs::create_dir_all("target/tmp");
        let req_path = format!("target/tmp/prop_det_req_{}.json", uuid::Uuid::new_v4());

        fs::write(&req_path, serde_json::to_string_pretty(&request).unwrap()).unwrap();

        // Run twice with same seed
        let out1 = format!("target/tmp/prop_det_out1_{}.json", uuid::Uuid::new_v4());
        let out2 = format!("target/tmp/prop_det_out2_{}.json", uuid::Uuid::new_v4());

        let status1 = Command::new("cargo")
            .args([
                "run", "--", "exec",
                "-f", &req_path,
                "--seed", &seed.to_string(),
                "--out", &out1,
            ])
            .env("MAGICRUNE_FORCE_WASM", "1")
            .status()
            .expect("Failed to execute");

        let status2 = Command::new("cargo")
            .args([
                "run", "--", "exec",
                "-f", &req_path,
                "--seed", &seed.to_string(),
                "--out", &out2,
            ])
            .env("MAGICRUNE_FORCE_WASM", "1")
            .status()
            .expect("Failed to execute");

        // If both succeeded, verify run_ids match
        if status1.success() && status2.success() {
            let result1: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(&out1).unwrap()
            ).unwrap();
            let result2: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(&out2).unwrap()
            ).unwrap();

            prop_assert_eq!(
                result1["run_id"].as_str().unwrap(),
                result2["run_id"].as_str().unwrap(),
                "Same request + seed should produce same run_id"
            );
        }

        // Cleanup
        let _ = fs::remove_file(&req_path);
        let _ = fs::remove_file(&out1);
        let _ = fs::remove_file(&out2);
    }

    #[test]
    fn prop_fs_policy_enforcement(
        forbidden_path in prop_oneof![
            Just("/etc/passwd".to_string()),
            Just("/home/user/secret.txt".to_string()),
            Just("/var/log/system.log".to_string()),
            "/[a-z]+/[a-z]+/[a-z]+.txt",
        ]
    ) {
        // Ensure path doesn't start with /tmp
        prop_assume!(!forbidden_path.starts_with("/tmp"));

        let request = serde_json::json!({
            "cmd": "echo test",
            "stdin": "",
            "env": {},
            "files": [{
                "path": forbidden_path,
                "content_b64": ""
            }],
            "policy_id": "default",
            "timeout_sec": 5,
            "allow_net": [],
            "allow_fs": []
        });

        let _ = fs::create_dir_all("target/tmp");
        let req_path = format!("target/tmp/prop_fs_{}.json", uuid::Uuid::new_v4());

        fs::write(&req_path, serde_json::to_string_pretty(&request).unwrap()).unwrap();

        let output = Command::new("cargo")
            .args(["run", "--", "exec", "-f", &req_path])
            .env("MAGICRUNE_FORCE_WASM", "1")
            .output()
            .expect("Failed to execute");

        // Should fail with policy violation
        prop_assert!(!output.status.success(), "Should reject forbidden path");

        let stderr = String::from_utf8_lossy(&output.stderr);
        prop_assert!(
            stderr.contains("policy: write denied") || stderr.contains("policy:"),
            "Should show policy error"
        );

        // Cleanup
        let _ = fs::remove_file(&req_path);
    }
}

// Add uuid dependency for unique file names
#[cfg(test)]
mod uuid {
    pub struct Uuid(u128);

    impl Uuid {
        pub fn new_v4() -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(nanos ^ (std::process::id() as u128))
        }
    }

    impl std::fmt::Display for Uuid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:032x}", self.0)
        }
    }
}
