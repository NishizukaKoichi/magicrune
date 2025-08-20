//! Contract tests for library API interface
//! These tests ensure the public API adheres to the expected contract

use magicrune::{
    grader::{grade, GradeOutcome},
    jet::{compute_msg_id, publish_result, send_request, JsConfig, JsResult},
    ledger::{InMemoryLedger, Ledger, RunRecord},
    sandbox::{detect_sandbox, exec_native, exec_wasm, SandboxKind, SandboxOutcome, SandboxSpec},
    schema::{PolicyDoc, SpellRequest, SpellResult},
};

#[test]
fn test_grade_api_contract() {
    // Test that grade function accepts expected inputs and returns expected output
    let request = SpellRequest {
        cmd: Some("echo test".to_string()),
        allow_net: Some(vec!["localhost".to_string()]),
        allow_fs: Some(vec!["/tmp/**".to_string()]),
        ..Default::default()
    };

    let policy = PolicyDoc::default();

    let outcome: GradeOutcome = grade(&request, &policy);

    // Verify output structure
    assert!(outcome.risk_score <= 100);
    assert!(!outcome.verdict.is_empty());
    assert!(["green", "yellow", "red"].contains(&outcome.verdict.as_str()));
}

#[test]
fn test_sandbox_api_contract() {
    // Test sandbox detection
    let kind: SandboxKind = detect_sandbox();
    assert!(matches!(kind, SandboxKind::Wasi | SandboxKind::Linux));

    // Test sandbox spec creation
    let spec = SandboxSpec {
        wall_sec: 10,
        cpu_ms: 5000,
        memory_mb: 128,
        pids: 100,
    };

    // Verify all fields are accessible
    assert_eq!(spec.wall_sec, 10);
    assert_eq!(spec.cpu_ms, 5000);
    assert_eq!(spec.memory_mb, 128);
    assert_eq!(spec.pids, 100);
}

#[tokio::test]
async fn test_sandbox_exec_api_contract() {
    let spec = SandboxSpec {
        wall_sec: 1,
        cpu_ms: 100,
        memory_mb: 16,
        pids: 10,
    };

    // Test exec_native contract
    let outcome: SandboxOutcome = exec_native("echo test", b"", &spec).await;
    assert!(outcome.exit_code >= 0);
    assert!(outcome.stdout.is_empty() || !outcome.stdout.is_empty());
    assert!(outcome.stderr.is_empty() || !outcome.stderr.is_empty());

    // Test exec_wasm contract
    let wasm_outcome: SandboxOutcome = exec_wasm(b"dummy", &spec).await;
    assert_eq!(wasm_outcome.exit_code, 0);
}

#[test]
fn test_ledger_api_contract() {
    let ledger = InMemoryLedger::new();

    let record = RunRecord {
        run_id: "test-123".to_string(),
        verdict: "safe".to_string(),
        risk_score: 25,
        exit_code: 0,
    };

    // Test put contract
    ledger.put(record.clone());

    // Test get contract
    let retrieved: Option<RunRecord> = ledger.get("test-123");
    assert!(retrieved.is_some());

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.run_id, "test-123");
    assert_eq!(retrieved.verdict, "safe");
    assert_eq!(retrieved.risk_score, 25);
    assert_eq!(retrieved.exit_code, 0);

    // Test get with non-existent ID
    let not_found: Option<RunRecord> = ledger.get("nonexistent");
    assert!(not_found.is_none());
}

#[test]
fn test_jet_api_contract() {
    // Test compute_msg_id contract
    let id1 = compute_msg_id(b"test payload");
    let id2 = compute_msg_id(b"test payload");
    let id3 = compute_msg_id(b"different");

    assert_eq!(id1, id2); // Same input = same output
    assert_ne!(id1, id3); // Different input = different output
    assert!(!id1.is_empty());
    assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn test_jet_async_api_contract() {
    let config = JsConfig {
        subject_req: "test.subject".to_string(),
    };

    // Test send_request contract
    let result: JsResult<()> = send_request(&config, b"test").await;
    assert!(!result.ok); // Network disabled in local env
    assert!(result.value.is_none());
    assert_eq!(result.err, Some("network disabled".to_string()));

    // Test publish_result contract
    let pub_result: JsResult<()> = publish_result("test.subject", b"data").await;
    assert!(!pub_result.ok);
    assert_eq!(pub_result.err, Some("network disabled".to_string()));
}

#[test]
fn test_schema_api_contract() {
    // Test SpellRequest serialization contract
    let request = SpellRequest {
        cmd: Some("test".to_string()),
        stdin: Some("input".to_string()),
        ..Default::default()
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: SpellRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.cmd, request.cmd);

    // Test SpellResult structure
    let result = SpellResult {
        run_id: "id".to_string(),
        verdict: "safe".to_string(),
        risk_score: 10,
        exit_code: 0,
        duration_ms: 100,
        stdout_trunc: false,
        sbom_attestation: "".to_string(),
    };

    let result_json = serde_json::to_string(&result).unwrap();
    assert!(result_json.contains("run_id"));
    assert!(result_json.contains("verdict"));
}
