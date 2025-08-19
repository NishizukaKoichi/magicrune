use std::process::Command;

fn run_req(cmd: &str, allow: &[&str]) -> i32 {
    // Write temp request
    std::fs::create_dir_all("target/tmp").ok();
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let reqp = format!("target/tmp/net_req_{}.json", ts);
    let body = serde_json::json!({
        "cmd": cmd,
        "stdin": "",
        "env": {},
        "files": [],
        "policy_id": "default",
        "timeout_sec": 5,
        "allow_net": [],
        "allow_fs": []
    });
    std::fs::write(reqp.clone(), serde_json::to_string_pretty(&body).unwrap()).unwrap();
    // Write temp policy
    let polp = format!("target/tmp/net_policy_{}.yml", ts);
    let allow_yaml: String = allow.iter().map(|a| format!("    - addr: \"{}\"\n", a)).collect();
    let pol = format!("version: 1\ncapabilities:\n  fs:\n    default: deny\n    allow:\n      - path: \"/tmp/**\"\n  net:\n    default: deny\n    allow:\n{}limits:\n  cpu_ms: 5000\n  memory_mb: 128\n  wall_sec: 5\n  pids: 64\n", allow_yaml);
    std::fs::write(polp.clone(), pol).unwrap();
    let st = Command::new("cargo")
        .args(["run","--bin","magicrune","--","exec","-f",&reqp,"--policy",&polp])
        .status().expect("run magicrune");
    st.code().unwrap_or(99)
}

#[test]
fn allow_ipv6_literal() {
    // IPv6 literal [::1]
    let code = run_req("echo test http://[::1]/", &[]);
    assert_eq!(code, 3); // disallowed
    let code2 = run_req("echo test http://[::1]/", &["[::1]"]);
    assert_eq!(code2, 0);
}

#[test]
fn allow_cidr_v4_v6_and_port_ranges() {
    let code = run_req("echo curl http://127.0.0.1:8085/", &["127.0.0.0/8", "2001:db8::/32"]);
    assert_eq!(code, 0);
    let code2 = run_req("echo curl http://127.0.0.1:9090/", &["127.0.0.1:8080-8090"]);
    assert_eq!(code2, 3);
    let code3 = run_req("echo curl https://api.example.com/", &["*.example.com:443"]);
    assert_eq!(code3, 0);
}
