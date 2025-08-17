use bootstrapped::sandbox::{detect_sandbox, SandboxKind};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SpellRequest {
    #[serde(default)]
    cmd: String,
    #[serde(default)]
    stdin: String,
    #[serde(default)]
    env: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    files: Vec<FileEntry>,
    #[serde(default)]
    policy_id: String,
    #[serde(default)]
    timeout_sec: u64,
    #[serde(default)]
    allow_net: Vec<String>,
    #[serde(default)]
    allow_fs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FileEntry {
    path: String,
    #[serde(default)]
    content_b64: String,
}

#[derive(Debug, Serialize)]
struct SpellResult {
    run_id: String,
    verdict: String,
    risk_score: u32,
    exit_code: i32,
    duration_ms: u64,
    stdout_trunc: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sbom_attestation: Option<String>,
}

// Minimal, portable SHA-256 implementation (reduced, local-only)
// Source: derived from FIPS PUB 180-4; implemented here to avoid extra deps.
fn sha256_hex(input: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64) * 8;
    let mut data = input.to_vec();
    data.push(0x80);
    while (data.len() % 64) != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in data.chunks(64) {
        let mut w = [0u32; 64];
        for (i, item) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *item = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for t in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    for v in h.iter() {
        out.push_str(&format!("{:08x}", v));
    }
    out
}

fn print_usage() {
    eprintln!(
        "Usage: magicrune exec -f <request.json> [--policy <policy.yml>] [--timeout <secs>] [--seed <n>] [--out <result.json>] [--strict]"
    );
}

#[derive(Debug, Clone)]
struct Thresholds {
    green: String,
    yellow: String,
    red: String,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            green: "<=20".to_string(),
            yellow: "21..=60".to_string(),
            red: ">=61".to_string(),
        }
    }
}

// Minimal YAML value extractor (line-oriented). Assumes keys are unique.
fn extract_yaml_scalar(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest0) = trimmed.strip_prefix(key) {
            let rest = rest0.trim();
            let val = rest.trim_start_matches(':').trim();
            return Some(val.trim_matches('"').to_string());
        }
    }
    None
}

fn load_thresholds_from_policy(path: &str) -> Thresholds {
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Thresholds::default(),
    };
    // Try to find explicit grading.thresholds entries
    // Fall back to defaults if missing.
    let green = extract_yaml_scalar(&text, "green").unwrap_or_else(|| "<=20".to_string());
    let yellow = extract_yaml_scalar(&text, "yellow").unwrap_or_else(|| "21..=60".to_string());
    let red = extract_yaml_scalar(&text, "red").unwrap_or_else(|| ">=61".to_string());
    Thresholds { green, yellow, red }
}

#[derive(Debug, Clone, Copy)]
struct PolicyLimits {
    wall_sec: u64,
    #[allow(dead_code)]
    cpu_ms: u64,
    #[allow(dead_code)]
    memory_mb: u64,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            wall_sec: 60,
            cpu_ms: 5000,
            memory_mb: 512,
        }
    }
}

fn extract_yaml_u64(content: &str, key: &str) -> Option<u64> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest0) = trimmed.strip_prefix(key) {
            let rest = rest0.trim();
            let val = rest.trim_start_matches(':').trim();
            if let Ok(v) = u64::from_str(val.trim_matches('"')) {
                return Some(v);
            }
        }
    }
    None
}

fn load_limits_from_policy(path: &str) -> PolicyLimits {
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return PolicyLimits::default(),
    };
    let wall_sec = extract_yaml_u64(&text, "wall_sec").unwrap_or(60);
    let cpu_ms = extract_yaml_u64(&text, "cpu_ms").unwrap_or(5000);
    let memory_mb = extract_yaml_u64(&text, "memory_mb").unwrap_or(512);
    PolicyLimits {
        wall_sec,
        cpu_ms,
        memory_mb,
    }
}

// Parse range expressions like "<=20", "21..=60", ">=61" and decide verdict.
fn decide_verdict_from_thresholds(score: u32, th: &Thresholds) -> &'static str {
    fn matches(expr: &str, n: u32) -> bool {
        let e = expr.trim();
        if let Some(rest) = e.strip_prefix("<=") {
            if let Ok(v) = u32::from_str(rest.trim()) {
                return n <= v;
            }
        }
        if let Some(rest) = e.strip_prefix(">=") {
            if let Ok(v) = u32::from_str(rest.trim()) {
                return n >= v;
            }
        }
        if let Some((a, b)) = e.split_once("..=") {
            if let (Ok(x), Ok(y)) = (u32::from_str(a.trim()), u32::from_str(b.trim())) {
                return n >= x && n <= y;
            }
        }
        false
    }
    // Touch `red` to avoid dead-code on the field when thresholds default is used
    let _ = &th.red;
    if matches(&th.green, score) {
        "green"
    } else if matches(&th.yellow, score) {
        "yellow"
    } else {
        "red"
    }
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<String>>();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_usage();
        std::process::exit(0);
    }

    if args[0] == "--version" {
        println!("magicrune 0.1.0");
        std::process::exit(0);
    }

    if args[0] != "exec" {
        eprintln!("unknown command: {}", args[0]);
        print_usage();
        std::process::exit(4);
    }

    // Defaults
    let mut in_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut _policy_path: Option<String> = None; // default: policies/default.policy.yml
    let mut _timeout: Option<u64> = None; // accepted but not enforced here
    let mut _seed: Option<u64> = None;
    let mut strict = false;

    // Parse flags
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--file" => {
                i += 1;
                in_path = args.get(i).cloned();
            }
            "--out" => {
                i += 1;
                out_path = args.get(i).cloned();
            }
            "--policy" => {
                i += 1;
                _policy_path = args.get(i).cloned();
            }
            "--timeout" => {
                i += 1;
                _timeout = args.get(i).and_then(|s| s.parse::<u64>().ok());
            }
            "--seed" => {
                i += 1;
                _seed = args.get(i).and_then(|s| s.parse::<u64>().ok());
            }
            "--strict" => {
                strict = true;
            }
            other if other.starts_with('-') => {
                eprintln!("unknown flag: {}", other);
                print_usage();
                std::process::exit(4);
            }
            _ => {}
        }
        i += 1;
    }

    let in_path = match in_path {
        Some(p) => p,
        None => {
            eprintln!("Missing -f <request.json>");
            print_usage();
            std::process::exit(1);
        }
    };

    let raw = match fs::read(&in_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read {}: {}", in_path, e);
            std::process::exit(1);
        }
    };

    let req_val: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid JSON in {}: {}", in_path, e);
            std::process::exit(1);
        }
    };

    // Also deserialize to typed struct for grading
    let req: SpellRequest = match serde_json::from_slice(&raw) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Invalid request shape: {}", e);
            std::process::exit(1);
        }
    };

    if strict {
        // Manual structural validation aligned with schemas (no external crates)
        fn is_string(v: &serde_json::Value) -> bool {
            matches!(v, serde_json::Value::String(_))
        }
        fn is_number(v: &serde_json::Value) -> bool {
            matches!(v, serde_json::Value::Number(_))
        }
        fn is_bool(v: &serde_json::Value) -> bool {
            matches!(v, serde_json::Value::Bool(_))
        }
        let required = [
            "cmd",
            "stdin",
            "env",
            "files",
            "policy_id",
            "timeout_sec",
            "allow_net",
            "allow_fs",
        ];
        for k in required.iter() {
            if req_val.get(*k).is_none() {
                eprintln!("schema: missing key: {}", k);
                std::process::exit(1);
            }
        }
        if !is_string(&req_val["cmd"]) {
            eprintln!("schema: cmd must be string");
            std::process::exit(1);
        }
        if !is_string(&req_val["stdin"]) {
            eprintln!("schema: stdin must be string");
            std::process::exit(1);
        }
        if !req_val["env"].is_object() {
            eprintln!("schema: env must be object");
            std::process::exit(1);
        }
        for (_k, v) in req_val["env"].as_object().unwrap() {
            if !(is_string(v) || is_number(v) || is_bool(v)) {
                eprintln!("schema: env values must be string/number/bool");
                std::process::exit(1);
            }
        }
        if !req_val["files"].is_array() {
            eprintln!("schema: files must be array");
            std::process::exit(1);
        }
        for f in req_val["files"].as_array().unwrap() {
            if !f.is_object() {
                eprintln!("schema: file entry must be object");
                std::process::exit(1);
            }
            if !f.get("path").map(is_string).unwrap_or(false) {
                eprintln!("schema: file.path must be string");
                std::process::exit(1);
            }
            if let Some(cb) = f.get("content_b64") {
                if !is_string(cb) {
                    eprintln!("schema: file.content_b64 must be string");
                    std::process::exit(1);
                }
            }
        }
        if !is_string(&req_val["policy_id"]) {
            eprintln!("schema: policy_id must be string");
            std::process::exit(1);
        }
        if !req_val["timeout_sec"].is_i64() && !req_val["timeout_sec"].is_u64() {
            eprintln!("schema: timeout_sec must be integer");
            std::process::exit(1);
        }
        let t = req_val["timeout_sec"]
            .as_i64()
            .unwrap_or_else(|| req_val["timeout_sec"].as_u64().unwrap_or(0) as i64);
        if !(0..=60).contains(&t) {
            eprintln!("schema: timeout_sec must be 0..=60");
            std::process::exit(1);
        }
        if !req_val["allow_net"].is_array() {
            eprintln!("schema: allow_net must be array");
            std::process::exit(1);
        }
        if !req_val["allow_fs"].is_array() {
            eprintln!("schema: allow_fs must be array");
            std::process::exit(1);
        }
    }

    // Deterministic run_id from request bytes + seed (SPEC: same request+seed => stable)
    let mut seed_buf = Vec::new();
    if let Some(s) = _seed {
        seed_buf.extend_from_slice(&s.to_le_bytes());
    }
    let mut all = raw.clone();
    all.extend_from_slice(&seed_buf);
    let run_id = format!("r_{}", sha256_hex(&all));

    // Minimal static grading (policy thresholds aware):
    // - if cmd suggests network and allow_net empty -> +40 (yellow)
    // - if cmd contains 'ssh' -> +30
    let cmd_l = req.cmd.to_lowercase();
    let mut risk_score: u32 = 0;
    let net_intent = cmd_l.contains("curl ")
        || cmd_l.contains("wget ")
        || cmd_l.contains("http://")
        || cmd_l.contains("https://");
    // Early policy enforcement
    let policy_path = _policy_path
        .or_else(|| std::env::var("MAGICRUNE_POLICY").ok())
        .unwrap_or_else(|| "policies/default.policy.yml".to_string());
    let limits = load_limits_from_policy(&policy_path);
    if net_intent && req.allow_net.is_empty() {
        eprintln!("policy: network is not allowed (allow_net is empty)");
        std::process::exit(3);
    }
    if req.timeout_sec > limits.wall_sec {
        eprintln!(
            "policy: timeout_sec {} exceeds wall_sec limit {}",
            req.timeout_sec, limits.wall_sec
        );
        std::process::exit(3);
    }

    if net_intent && req.allow_net.is_empty() {
        risk_score += 40; // still reflected in risk if allowed via policy elsewhere
    }
    if cmd_l.contains("ssh ") {
        risk_score += 30;
    }

    // Load thresholds from policy (if available)
    let thresholds = load_thresholds_from_policy(&policy_path);
    let verdict = decide_verdict_from_thresholds(risk_score, &thresholds);

    // Exit code mapping
    let exit_code = match verdict {
        "green" => 0,
        "yellow" => 10,
        _ => 20,
    };

    // Minimal file materialization with policy check (allow_fs)
    // Only allow writes under /tmp/** unless policy explicitly allows broader paths.
    if !req.files.is_empty() {
        for f in &req.files {
            let p = Path::new(&f.path);
            let allowed_tmp = p.starts_with("/tmp/");
            let mut allowed = allowed_tmp; // default allow only /tmp/**
            if !req.allow_fs.is_empty() {
                for pat in &req.allow_fs {
                    if pat == "/tmp/**" && allowed_tmp {
                        allowed = true;
                        break;
                    }
                    // very simple contains check for explicit paths
                    if pat == &f.path {
                        allowed = true;
                        break;
                    }
                }
            }
            if !allowed {
                eprintln!("policy: write denied for {}", f.path);
                std::process::exit(3);
            }
            if let Some(dir) = p.parent() {
                let _ = fs::create_dir_all(dir);
            }
            if !f.content_b64.is_empty() {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&f.content_b64)
                {
                    if let Err(e) = fs::write(p, &bytes) {
                        eprintln!("write failed: {}: {}", f.path, e);
                        std::process::exit(4);
                    }
                }
            } else if let Err(e) = fs::write(p, []) {
                eprintln!("write failed: {}: {}", f.path, e);
                std::process::exit(4);
            }
        }
    }

    // Optionally execute the command once.
    // - Linux+native: run locally (placeholder for true sandbox)
    // - Otherwise (WASI default): skip here (feature-gated path elsewhere)
    // - MAGICRUNE_DRY_RUN=1 to skip entirely
    let mut captured_stdout: Vec<u8> = Vec::new();
    let mut captured_stderr: Vec<u8> = Vec::new();
    let mut actual_exit: Option<i32> = None;
    let mut forced_timeout_red = false;
    let mut duration_ms: u64 = 0;
    if std::env::var("MAGICRUNE_DRY_RUN").ok().as_deref() != Some("1") && !req.cmd.trim().is_empty()
    {
        match detect_sandbox() {
            SandboxKind::Linux => {
                let started = Instant::now();
                let mut child = Command::new("bash")
                    .arg("-lc")
                    .arg(&req.cmd)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("spawn bash");
                if !req.stdin.is_empty() {
                    use std::io::Write as _;
                    if let Some(mut sin) = child.stdin.take() {
                        let _ = sin.write_all(req.stdin.as_bytes());
                    }
                }
                let deadline = Instant::now() + Duration::from_secs(limits.wall_sec);
                loop {
                    if let Ok(Some(_status)) = child.try_wait() {
                        let out = child.wait_with_output().expect("collect output after exit");
                        duration_ms = started.elapsed().as_millis() as u64;
                        captured_stdout = out.stdout.clone();
                        captured_stderr = out.stderr.clone();
                        actual_exit = out.status.code();
                        break;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        forced_timeout_red = true;
                        duration_ms = started.elapsed().as_millis() as u64;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
            SandboxKind::Wasi => {
                // No-op here; WASI execution is wired in sandbox module when feature is enabled.
            }
        }
    }

    let result = SpellResult {
        run_id,
        verdict: verdict.to_string(),
        risk_score,
        exit_code: actual_exit.unwrap_or(exit_code),
        duration_ms,
        stdout_trunc: false,
        sbom_attestation: None,
    };

    // If runtime timeout was hit, force red verdict and exit=20
    let mut out_json = serde_json::to_string_pretty(&result).expect("serialize");
    let mut final_exit = result.exit_code;
    if forced_timeout_red {
        let mut v: serde_json::Value = serde_json::from_str(&out_json).unwrap();
        v["verdict"] = serde_json::Value::String("red".to_string());
        v["exit_code"] = serde_json::Value::Number(20u64.into());
        out_json = serde_json::to_string_pretty(&v).unwrap();
        final_exit = 20;
    }
    // Output schema minimal validation under --strict
    if strict {
        // Ensure required keys and types
        let out_val: serde_json::Value = serde_json::from_str(&out_json).unwrap();
        let reqd = [
            "run_id",
            "verdict",
            "risk_score",
            "exit_code",
            "duration_ms",
            "stdout_trunc",
        ];
        for k in reqd.iter() {
            if out_val.get(*k).is_none() {
                eprintln!("output schema: missing {}", k);
                std::process::exit(2);
            }
        }
        if !matches!(out_val["run_id"], serde_json::Value::String(_)) {
            eprintln!("output schema: run_id");
            std::process::exit(2);
        }
        if !matches!(out_val["verdict"], serde_json::Value::String(_)) {
            eprintln!("output schema: verdict");
            std::process::exit(2);
        }
        if !matches!(out_val["risk_score"], serde_json::Value::Number(_)) {
            eprintln!("output schema: risk_score");
            std::process::exit(2);
        }
        if !matches!(out_val["exit_code"], serde_json::Value::Number(_)) {
            eprintln!("output schema: exit_code");
            std::process::exit(2);
        }
        if !matches!(out_val["duration_ms"], serde_json::Value::Number(_)) {
            eprintln!("output schema: duration_ms");
            std::process::exit(2);
        }
        if !matches!(out_val["stdout_trunc"], serde_json::Value::Bool(_)) {
            eprintln!("output schema: stdout_trunc");
            std::process::exit(2);
        }
    }

    if let Some(p) = out_path {
        if let Some(dir) = Path::new(&p).parent() {
            if !dir.as_os_str().is_empty() && !dir.exists() {
                if let Err(e) = fs::create_dir_all(dir) {
                    eprintln!("Failed to create output dir: {}", e);
                    std::process::exit(4);
                }
            }
        }
        if let Err(e) = fs::write(&p, out_json.as_bytes()) {
            eprintln!("Failed to write {}: {}", p, e);
            std::process::exit(4);
        }
    } else {
        let mut stdout = io::stdout();
        let _ = stdout.write_all(out_json.as_bytes());
    }

    // Quarantine for red verdict (write result + captured stdout/stderr if any)
    if forced_timeout_red || final_exit == 20 {
        let qdir = Path::new("quarantine");
        let _ = fs::create_dir_all(qdir);
        let _ = fs::write(qdir.join("result.red.json"), out_json.as_bytes());
        let _ = fs::write(qdir.join("stdout.txt"), &captured_stdout);
        let _ = fs::write(qdir.join("stderr.txt"), &captured_stderr);
    }

    std::process::exit(final_exit);
}
