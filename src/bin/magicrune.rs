use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
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
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
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
        for i in 0..16 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
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
    let mut _policy_path: Option<String> = None; // accepted but not enforced here
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
        fn is_string(v: &serde_json::Value) -> bool { matches!(v, serde_json::Value::String(_)) }
        fn is_number(v: &serde_json::Value) -> bool { matches!(v, serde_json::Value::Number(_)) }
        fn is_bool(v: &serde_json::Value) -> bool { matches!(v, serde_json::Value::Bool(_)) }
        let required = ["cmd","stdin","env","files","policy_id","timeout_sec","allow_net","allow_fs"];
        for k in required.iter() { if !req_val.get(*k).is_some() { eprintln!("schema: missing key: {}", k); std::process::exit(1); } }
        if !is_string(&req_val["cmd"]) { eprintln!("schema: cmd must be string"); std::process::exit(1); }
        if !is_string(&req_val["stdin"]) { eprintln!("schema: stdin must be string"); std::process::exit(1); }
        if !req_val["env"].is_object() { eprintln!("schema: env must be object"); std::process::exit(1); }
        for (_k, v) in req_val["env"].as_object().unwrap() { if !(is_string(v) || is_number(v) || is_bool(v)) { eprintln!("schema: env values must be string/number/bool"); std::process::exit(1); } }
        if !req_val["files"].is_array() { eprintln!("schema: files must be array"); std::process::exit(1); }
        for f in req_val["files"].as_array().unwrap() {
            if !f.is_object() { eprintln!("schema: file entry must be object"); std::process::exit(1); }
            if !f.get("path").map(|v| is_string(v)).unwrap_or(false) { eprintln!("schema: file.path must be string"); std::process::exit(1); }
            if let Some(cb) = f.get("content_b64") { if !is_string(cb) { eprintln!("schema: file.content_b64 must be string"); std::process::exit(1); } }
        }
        if !is_string(&req_val["policy_id"]) { eprintln!("schema: policy_id must be string"); std::process::exit(1); }
        if !req_val["timeout_sec"].is_i64() && !req_val["timeout_sec"].is_u64() { eprintln!("schema: timeout_sec must be integer"); std::process::exit(1); }
        let t = req_val["timeout_sec"].as_i64().unwrap_or_else(|| req_val["timeout_sec"].as_u64().unwrap_or(0) as i64);
        if !(0..=60).contains(&t) { eprintln!("schema: timeout_sec must be 0..=60"); std::process::exit(1); }
        if !req_val["allow_net"].is_array() { eprintln!("schema: allow_net must be array"); std::process::exit(1); }
        if !req_val["allow_fs"].is_array() { eprintln!("schema: allow_fs must be array"); std::process::exit(1); }
    }

    // Deterministic run_id from request bytes + seed (SPEC: same request+seed => stable)
    let mut seed_buf = Vec::new();
    if let Some(s) = _seed { seed_buf.extend_from_slice(&s.to_le_bytes()); }
    let mut all = raw.clone(); all.extend_from_slice(&seed_buf);
    let run_id = format!("r_{}", sha256_hex(&all));

    // Minimal static grading (SPEC thresholds):
    // - if cmd suggests network and allow_net empty -> +40 (yellow)
    // - if cmd contains 'ssh' -> +30
    let cmd_l = req.cmd.to_lowercase();
    let mut risk_score: u32 = 0;
    let net_intent = cmd_l.contains("curl ") || cmd_l.contains("wget ") || cmd_l.contains("http://") || cmd_l.contains("https://");
    if net_intent && req.allow_net.is_empty() {
        risk_score += 40;
    }
    if cmd_l.contains("ssh ") {
        risk_score += 30;
    }

    // Verdict mapping
    let verdict = if risk_score <= 20 {
        "green"
    } else if risk_score <= 60 {
        "yellow"
    } else {
        "red"
    };

    // Exit code mapping
    let exit_code = match verdict {
        "green" => 0,
        "yellow" => 10,
        _ => 20,
    };

    let result = SpellResult {
        run_id,
        verdict: verdict.to_string(),
        risk_score,
        exit_code,
        duration_ms: 0,
        stdout_trunc: false,
        sbom_attestation: None,
    };

    let out_json = serde_json::to_string_pretty(&result).expect("serialize");
    // Output schema minimal validation under --strict
    if strict {
        // Ensure required keys and types
        let out_val: serde_json::Value = serde_json::from_str(&out_json).unwrap();
        let reqd = ["run_id","verdict","risk_score","exit_code","duration_ms","stdout_trunc"];
        for k in reqd.iter() { if !out_val.get(*k).is_some() { eprintln!("output schema: missing {}", k); std::process::exit(2); } }
        if !matches!(out_val["run_id"], serde_json::Value::String(_)) { eprintln!("output schema: run_id"); std::process::exit(2); }
        if !matches!(out_val["verdict"], serde_json::Value::String(_)) { eprintln!("output schema: verdict"); std::process::exit(2); }
        if !matches!(out_val["risk_score"], serde_json::Value::Number(_)) { eprintln!("output schema: risk_score"); std::process::exit(2); }
        if !matches!(out_val["exit_code"], serde_json::Value::Number(_)) { eprintln!("output schema: exit_code"); std::process::exit(2); }
        if !matches!(out_val["duration_ms"], serde_json::Value::Number(_)) { eprintln!("output schema: duration_ms"); std::process::exit(2); }
        if !matches!(out_val["stdout_trunc"], serde_json::Value::Bool(_)) { eprintln!("output schema: stdout_trunc"); std::process::exit(2); }
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

    // Quarantine placeholder for red verdict (write result + empty stdout/stderr)
    if exit_code == 20 {
        let qdir = Path::new("quarantine");
        let _ = fs::create_dir_all(qdir);
        let _ = fs::write(qdir.join("result.red.json"), out_json.as_bytes());
        let _ = fs::write(qdir.join("stdout.txt"), b"");
        let _ = fs::write(qdir.join("stderr.txt"), b"");
    }

    std::process::exit(exit_code);
}
