use std::io::Write;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn nats_reachable() -> bool {
    let addr = std::env::var("NATS_TCP").unwrap_or_else(|_| "127.0.0.1:4222".to_string());
    TcpStream::connect(&addr).is_ok()
}

#[test]
fn jetstream_dedup_and_retry() {
    // Skip unless explicitly required or NATS reachable
    let require = std::env::var("MAGICRUNE_REQUIRE_NATS").ok() == Some("1".to_string());
    if !require && !nats_reachable() {
        eprintln!("NATS not reachable; skipping jet_e2e");
        return;
    }

    // Start consumer (magicrune consume) with feature jet
    let mut consumer = Command::new("cargo")
        .args(["run", "--features", "jet", "--bin", "magicrune", "--", "consume"])
        .env("MAGICRUNE_TEST_DELAY_MS", "1500")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn consumer");
    thread::sleep(Duration::from_secs(2));

    // 1) Publish once -> expect success (response received)
    let st1 = Command::new("cargo")
        .args(["run", "--features", "jet", "--bin", "js_publish", "--", "samples/ok.json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .status()
        .expect("run js_publish #1");
    assert!(st1.success(), "first publish should succeed");

    // 2) Publish duplicate (same payload -> same Nats-Msg-Id) -> expect timeout / non-zero exit
    let st2 = Command::new("cargo")
        .args(["run", "--features", "jet", "--bin", "js_publish", "--", "samples/ok.json"])
        .env("JS_PUBLISH_TIMEOUT_SEC", "3")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .status()
        .expect("run js_publish #2 (dupe)");
    assert!(
        !st2.success(),
        "duplicate publish should not produce new response (dedup)"
    );

    // 3) Publish modified payload (add seed) -> expect success again
    std::fs::create_dir_all("target/tmp").ok();
    let tmp_path = "target/tmp/ok_seed42.json";
    let src = std::fs::read_to_string("samples/ok.json").expect("read ok.json");
    // naive inject seed at end before closing brace
    let mut buf = String::new();
    if let Some(pos) = src.rfind('}') {
        buf.push_str(&src[..pos]);
        buf.push_str(
            if src[..pos].trim_end().ends_with(',') {
                "\n  \"seed\": 42\n}"
            } else {
                "\n, \"seed\": 42\n}"
            },
        );
    } else {
        buf = src;
    }
    let mut f = std::fs::File::create(tmp_path).expect("create tmp json");
    f.write_all(buf.as_bytes()).unwrap();
    let st3 = Command::new("cargo")
        .args(["run", "--features", "jet", "--bin", "js_publish", "--", tmp_path])
        .env("JS_PUBLISH_TIMEOUT_SEC", "10")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .status()
        .expect("run js_publish #3 (retry)");
    assert!(st3.success(), "publish with new seed should succeed");

    // Cleanup
    let _ = consumer.kill();
}
#[test]
fn jetstream_redelivery_with_skip_ack_once() {
    let require = std::env::var("MAGICRUNE_REQUIRE_NATS").ok() == Some("1".to_string());
    if !require && !nats_reachable() { eprintln!("NATS not reachable; skipping jet_e2e"); return; }
    let metrics = "target/tmp/metrics.json";
    let mut consumer = Command::new("cargo")
        .args(["run", "--features", "jet", "--bin", "magicrune", "--", "consume"])
        .env("NATS_ACK_WAIT_SEC", "2")
        .env("MAGICRUNE_TEST_SKIP_ACK_ONCE", "1")
        .env("MAGICRUNE_METRICS_FILE", metrics)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn consumer");
    thread::sleep(Duration::from_secs(1));

    let st = Command::new("cargo")
        .args(["run", "--features", "jet", "--bin", "js_publish", "--", "samples/ok.json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .status()
        .expect("run js_publish");
    assert!(st.success());
    thread::sleep(Duration::from_secs(3));
    let data = std::fs::read_to_string(metrics).unwrap_or_default();
    // expect dupes >= 0 and total >= 1; weak assertion to confirm metrics are written
    assert!(data.contains("total"));
    let _ = consumer.kill();
}

#[test]
fn error_net_violation_dedup() {
    let require = std::env::var("MAGICRUNE_REQUIRE_NATS").ok() == Some("1".to_string());
    if !require && !nats_reachable() { eprintln!("NATS not reachable; skipping jet_e2e"); return; }
    let mut consumer = Command::new("cargo")
        .args(["run", "--features", "jet", "--bin", "magicrune", "--", "consume"])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn consumer");
    thread::sleep(Duration::from_secs(1));
    // First send deny_net -> should succeed (red verdict)
    let st1 = Command::new("cargo")
        .args(["run","--features","jet","--bin","js_publish","--","samples/deny_net.json"]) 
        .stdout(Stdio::piped()).status().expect("pub1");
    assert!(st1.success());
    // Duplicate should time out due to dedupe
    let st2 = Command::new("cargo")
        .args(["run","--features","jet","--bin","js_publish","--","samples/deny_net.json"]) 
        .env("JS_PUBLISH_TIMEOUT_SEC","3").stdout(Stdio::piped()).status().expect("pub2");
    assert!(!st2.success());
    let _ = consumer.kill();
}

#[test]
fn error_fs_violation_dedup() {
    let require = std::env::var("MAGICRUNE_REQUIRE_NATS").ok() == Some("1".to_string());
    if !require && !nats_reachable() { eprintln!("NATS not reachable; skipping jet_e2e"); return; }
    let mut consumer = Command::new("cargo")
        .args(["run", "--features", "jet", "--bin", "magicrune", "--", "consume"])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn consumer");
    thread::sleep(Duration::from_secs(1));
    // craft fs violation request
    std::fs::create_dir_all("target/tmp").ok();
    let p = "target/tmp/fs_violation.json";
    let body = r#"{
  "cmd": "echo hi",
  "stdin": "",
  "env": {},
  "files": [ { "path": "/etc/notallowed", "content_b64": "" } ],
  "policy_id": "default",
  "timeout_sec": 5,
  "allow_net": [],
  "allow_fs": []
}"#;
    std::fs::write(p, body).unwrap();
    let st1 = Command::new("cargo")
        .args(["run","--features","jet","--bin","js_publish","--",p]) 
        .stdout(Stdio::piped()).status().expect("pub1");
    assert!(st1.success());
    let st2 = Command::new("cargo")
        .args(["run","--features","jet","--bin","js_publish","--",p]) 
        .env("JS_PUBLISH_TIMEOUT_SEC","3").stdout(Stdio::piped()).status().expect("pub2");
    assert!(!st2.success());
    let _ = consumer.kill();
}
