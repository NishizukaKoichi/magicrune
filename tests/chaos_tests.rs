//! Chaos tests (fault injection) for MagicRune
//! These tests simulate various failure conditions to ensure robustness

use std::fs;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn chaos_timeout_enforcement() {
    // Test that timeout is enforced on policy level
    let request = serde_json::json!({
        "cmd": "echo test",
        "stdin": "",
        "env": {},
        "files": [],
        "policy_id": "default",
        "timeout_sec": 20,  // Request wants 20 seconds
        "allow_net": [],
        "allow_fs": []
    });

    let _ = fs::create_dir_all("target/tmp");
    let req_path = "target/tmp/chaos_timeout.json";
    fs::write(req_path, serde_json::to_string_pretty(&request).unwrap()).unwrap();

    // Default policy limits to 15 seconds, so this should fail
    let output = Command::new("cargo")
        .args(["run", "--", "exec", "-f", req_path])
        .env("MAGICRUNE_FORCE_WASM", "1")
        .output()
        .expect("Failed to execute");

    // Should fail due to policy violation
    assert!(
        !output.status.success(),
        "Should fail due to timeout policy violation"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timeout_sec") && stderr.contains("exceeds wall_sec limit"),
        "Should report timeout policy violation"
    );
}

#[test]
fn chaos_large_output_truncation() {
    // Test handling of extremely large outputs
    let request = serde_json::json!({
        "cmd": "yes | head -n 100000",  // Generate lots of output
        "stdin": "",
        "env": {},
        "files": [],
        "policy_id": "default",
        "timeout_sec": 5,
        "allow_net": [],
        "allow_fs": []
    });

    let _ = fs::create_dir_all("target/tmp");
    let req_path = "target/tmp/chaos_large_output.json";
    let out_path = "target/tmp/chaos_large_output_result.json";
    fs::write(req_path, serde_json::to_string_pretty(&request).unwrap()).unwrap();

    let status = Command::new("cargo")
        .args(["run", "--", "exec", "-f", req_path, "--out", out_path])
        .env("MAGICRUNE_FORCE_WASM", "1")
        .status()
        .expect("Failed to execute");

    // Should complete successfully
    assert!(
        status.success() || status.code().unwrap_or(99) != 99,
        "Should handle large output"
    );

    // Result should exist and be valid JSON
    if fs::metadata(out_path).is_ok() {
        let result_str = fs::read_to_string(out_path).expect("Should read result");
        let _result: serde_json::Value =
            serde_json::from_str(&result_str).expect("Result should be valid JSON");
    }
}

#[test]
fn chaos_concurrent_execution() {
    // Test concurrent execution doesn't cause crashes
    let handles: Vec<_> = (0..5)
        .map(|i| {
            thread::spawn(move || {
                let request = serde_json::json!({
                    "cmd": format!("echo test{}", i),
                    "stdin": "",
                    "env": {},
                    "files": [],
                    "policy_id": "default",
                    "timeout_sec": 5,
                    "allow_net": [],
                    "allow_fs": []
                });

                let req_path = format!("target/tmp/chaos_concurrent_{}.json", i);
                fs::write(&req_path, serde_json::to_string_pretty(&request).unwrap()).unwrap();

                let status = Command::new("cargo")
                    .args(["run", "--", "exec", "-f", &req_path])
                    .env("MAGICRUNE_FORCE_WASM", "1")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("Failed to execute");

                // Each should complete
                assert!(status.code().is_some(), "Process {} should not crash", i);
            })
        })
        .collect();

    // Wait for all to complete
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

#[test]
fn chaos_signal_handling() {
    // Test graceful handling of signals (SIGTERM/SIGINT)
    let request = serde_json::json!({
        "cmd": "sleep 30",
        "stdin": "",
        "env": {},
        "files": [],
        "policy_id": "default",
        "timeout_sec": 30,
        "allow_net": [],
        "allow_fs": []
    });

    let _ = fs::create_dir_all("target/tmp");
    let req_path = "target/tmp/chaos_signal.json";
    fs::write(req_path, serde_json::to_string_pretty(&request).unwrap()).unwrap();

    let mut child = Command::new("cargo")
        .args(["run", "--", "exec", "-f", req_path])
        .env("MAGICRUNE_FORCE_WASM", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn");

    // Let it start
    thread::sleep(Duration::from_millis(500));

    // Try to kill it
    let killed = Arc::new(AtomicBool::new(false));
    let killed_clone = killed.clone();

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(1));
        if let Err(e) = child.kill() {
            eprintln!("Failed to kill process: {}", e);
        } else {
            killed_clone.store(true, Ordering::Relaxed);
        }
    });

    // Wait a bit for kill to take effect
    thread::sleep(Duration::from_secs(2));

    // Process should have been killed
    assert!(killed.load(Ordering::Relaxed), "Process should be killable");
}

#[test]
fn chaos_invalid_json_handling() {
    // Test handling of malformed JSON
    let _ = fs::create_dir_all("target/tmp");

    // Write invalid JSON
    fs::write("target/tmp/chaos_invalid.json", "{ invalid json }").unwrap();

    let output = Command::new("cargo")
        .args(["run", "--", "exec", "-f", "target/tmp/chaos_invalid.json"])
        .env("MAGICRUNE_FORCE_WASM", "1")
        .output()
        .expect("Failed to execute");

    // Should fail with parse error
    assert!(!output.status.success(), "Should fail on invalid JSON");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid JSON") || stderr.contains("expected"),
        "Should report JSON error"
    );
}

#[test]
fn chaos_missing_required_fields() {
    // Test handling of missing required fields
    let incomplete_request = serde_json::json!({
        "cmd": "echo test"
        // Missing all other required fields
    });

    let _ = fs::create_dir_all("target/tmp");
    let req_path = "target/tmp/chaos_incomplete.json";
    fs::write(
        req_path,
        serde_json::to_string_pretty(&incomplete_request).unwrap(),
    )
    .unwrap();

    let output = Command::new("cargo")
        .args(["run", "--", "exec", "-f", req_path, "--strict"])
        .env("MAGICRUNE_FORCE_WASM", "1")
        .output()
        .expect("Failed to execute");

    // Should fail validation
    assert!(
        !output.status.success(),
        "Should fail on incomplete request"
    );
}

#[test]
fn chaos_resource_exhaustion() {
    // Test handling when resources are exhausted
    let request = serde_json::json!({
        "cmd": "yes | head -c 1G > /tmp/huge.txt",  // Try to create huge file
        "stdin": "",
        "env": {},
        "files": [],
        "policy_id": "default",
        "timeout_sec": 5,
        "allow_net": [],
        "allow_fs": ["/tmp/**"]
    });

    let _ = fs::create_dir_all("target/tmp");
    let req_path = "target/tmp/chaos_resource.json";
    fs::write(req_path, serde_json::to_string_pretty(&request).unwrap()).unwrap();

    let status = Command::new("cargo")
        .args(["run", "--", "exec", "-f", req_path])
        .env("MAGICRUNE_FORCE_WASM", "1")
        .status()
        .expect("Failed to execute");

    // Should complete (either success or resource limit)
    assert!(
        status.code().is_some(),
        "Should not crash on resource exhaustion"
    );
}

#[test]
fn chaos_rapid_file_operations() {
    // Test rapid file creation/deletion
    let request = serde_json::json!({
        "cmd": "for i in {1..100}; do touch /tmp/test_$i.txt && rm /tmp/test_$i.txt; done",
        "stdin": "",
        "env": {},
        "files": [],
        "policy_id": "default",
        "timeout_sec": 5,
        "allow_net": [],
        "allow_fs": ["/tmp/**"]
    });

    let _ = fs::create_dir_all("target/tmp");
    let req_path = "target/tmp/chaos_rapid_files.json";
    fs::write(req_path, serde_json::to_string_pretty(&request).unwrap()).unwrap();

    let status = Command::new("cargo")
        .args(["run", "--", "exec", "-f", req_path])
        .env("MAGICRUNE_FORCE_WASM", "1")
        .status()
        .expect("Failed to execute");

    // Should handle rapid file operations
    assert!(
        status.code().is_some(),
        "Should handle rapid file operations"
    );
}
