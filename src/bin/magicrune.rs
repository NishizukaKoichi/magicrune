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

// --- env helpers ------------------------------------------------------------
#[inline]
fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

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
        "Usage:\n  magicrune exec -f <request.json> [--policy <policy.yml>] [--timeout <secs>] [--seed <n>] [--out <result.json>] [--strict]\n  magicrune consume [--url <nats_host:port>] [--subject <run.req.*>]"
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
fn extract_yaml_scalar_under(content: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    let mut section_indent: Option<usize> = None;
    for line in content.lines() {
        let raw = line;
        let trimmed = raw.trim_end();
        let indent = raw.chars().take_while(|c| c.is_whitespace()).count();
        if trimmed.trim_start().starts_with('#') {
            continue;
        }
        if trimmed.trim() == format!("{}:", section) {
            in_section = true;
            section_indent = Some(indent);
            continue;
        }
        if in_section {
            // If indentation drops back to or above section start, section ends
            if let Some(si) = section_indent {
                if indent <= si && !trimmed.trim().is_empty() {
                    in_section = false;
                }
            }
            if in_section {
                let t = trimmed.trim();
                if let Some(rest0) = t.strip_prefix(key) {
                    let rest = rest0.trim();
                    let val = rest.trim_start_matches(':').trim();
                    return Some(val.trim_matches('"').to_string());
                }
            }
        }
    }
    None
}

fn load_thresholds_from_policy(path: &str) -> Thresholds {
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Thresholds::default(),
    };
    // Look specifically under grading -> thresholds
    let green = extract_yaml_scalar_under(&text, "thresholds", "green")
        .or_else(|| extract_yaml_scalar_under(&text, "grading", "green"))
        .unwrap_or_else(|| "<=20".to_string());
    let yellow = extract_yaml_scalar_under(&text, "thresholds", "yellow")
        .or_else(|| extract_yaml_scalar_under(&text, "grading", "yellow"))
        .unwrap_or_else(|| "21..=60".to_string());
    let red = extract_yaml_scalar_under(&text, "thresholds", "red")
        .or_else(|| extract_yaml_scalar_under(&text, "grading", "red"))
        .unwrap_or_else(|| ">=61".to_string());
    Thresholds { green, yellow, red }
}

#[derive(Debug, Clone, Copy)]
struct PolicyLimits {
    wall_sec: u64,
    #[allow(dead_code)]
    cpu_ms: u64,
    #[allow(dead_code)]
    memory_mb: u64,
    #[allow(dead_code)]
    pids: u64,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            wall_sec: 60,
            cpu_ms: 5000,
            memory_mb: 512,
            pids: 256,
        }
    }
}

fn extract_yaml_u64_under(content: &str, section: &str, key: &str) -> Option<u64> {
    let mut in_section = false;
    let mut section_indent: Option<usize> = None;
    for line in content.lines() {
        let raw = line;
        let trimmed = raw.trim_end();
        let indent = raw.chars().take_while(|c| c.is_whitespace()).count();
        if trimmed.trim_start().starts_with('#') {
            continue;
        }
        if trimmed.trim() == format!("{}:", section) {
            in_section = true;
            section_indent = Some(indent);
            continue;
        }
        if in_section {
            if let Some(si) = section_indent {
                if indent <= si && !trimmed.trim().is_empty() {
                    in_section = false;
                }
            }
            if in_section {
                let t = trimmed.trim();
                if let Some(rest0) = t.strip_prefix(key) {
                    let rest = rest0.trim();
                    let val = rest.trim_start_matches(':').trim();
                    if let Ok(v) = u64::from_str(val.trim_matches('"')) {
                        return Some(v);
                    }
                }
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
    let wall_sec = extract_yaml_u64_under(&text, "limits", "wall_sec").unwrap_or(60);
    let cpu_ms = extract_yaml_u64_under(&text, "limits", "cpu_ms").unwrap_or(5000);
    let memory_mb = extract_yaml_u64_under(&text, "limits", "memory_mb").unwrap_or(512);
    let pids = extract_yaml_u64_under(&text, "limits", "pids").unwrap_or(256);
    PolicyLimits {
        wall_sec,
        cpu_ms,
        memory_mb,
        pids,
    }
}

// Minimal YAML walker to extract capabilities.net.allow host[:port] entries
fn load_net_allow_from_policy(path: &str) -> Vec<String> {
    let text = match std::fs::read_to_string(path) { Ok(s) => s, Err(_) => return vec![] };
    let mut out = Vec::new();
    let mut in_caps = false;
    let mut in_net = false;
    let mut in_allow = false;
    let mut caps_indent = 0usize;
    let mut net_indent = 0usize;
    let mut allow_indent = 0usize;
    for raw in text.lines() {
        let indent = raw.chars().take_while(|c| c.is_whitespace()).count();
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        if !in_caps && line == "capabilities:" { in_caps = true; caps_indent = indent; continue; }
        if in_caps {
            if indent <= caps_indent { in_caps = false; in_net = false; in_allow = false; }
            if !in_net && line == "net:" { in_net = true; net_indent = indent; continue; }
            if in_net {
                if indent <= net_indent { in_net = false; in_allow = false; }
                if !in_allow && line == "allow:" { in_allow = true; allow_indent = indent; continue; }
                if in_allow {
                    if indent <= allow_indent { in_allow = false; }
                    if line.starts_with("- ") {
                        let item = line.trim_start_matches("- ").trim();
                        // Support both:
                        // - host: "example.com:443" (keyed form)
                        // - "example.com:443" (simple string form)
                        if let Some((key, val)) = item.split_once(": ") {
                            let v = val.trim().trim_matches('"');
                            if !v.is_empty() { out.push(v.to_string()); }
                        } else {
                            let v = item.trim().trim_matches('"');
                            if !v.is_empty() { out.push(v.to_string()); }
                        }
                    }
                }
            }
        }
    }
    out
}

// Extract http/https host[:port] occurrences from a command line string
fn extract_http_hosts(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    for scheme in ["http://", "https://"].iter() {
        let mut i = 0usize;
        while let Some(pos) = cmd[i..].find(scheme) {
            let start = i + pos + scheme.len();
            let rest = &cmd[start..];
            // host[:port] until first '/' or space
            let end = rest.find(|c: char| c == '/' || c.is_whitespace()).unwrap_or(rest.len());
            let hostport = &rest[..end];
            if !hostport.is_empty() {
                let default_port = if *scheme == "https://" { "443" } else { "80" };
                let (h, p) = hostport_parts(hostport);
                let hp = if p.is_none() {
                    format!("{}:{}", h, default_port)
                } else {
                    hostport.to_string()
                };
                out.push(hp);
            }
            i = start + end;
        }
    }
    out
}

fn hostport_parts(s: &str) -> (std::borrow::Cow<str>, Option<&str>) {
    let st = s.trim();
    if let Some(rest) = st.strip_prefix('[') {
        if let Some(pos) = rest.find(']') {
            let host = &rest[..pos];
            let after = &rest[pos+1..];
            if let Some(p) = after.strip_prefix(':') { return (std::borrow::Cow::Owned(host.to_string()), Some(p)); }
            return (std::borrow::Cow::Owned(host.to_string()), None);
        }
    }
    if let Some((h,p)) = st.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) { return (std::borrow::Cow::Owned(h.to_string()), Some(p)); }
    }
    (std::borrow::Cow::Borrowed(st), None)
}

fn parse_port_spec(p: Option<&str>) -> (bool, Option<(u16,u16)>) {
    if let Some(ps) = p {
        if ps == "*" { return (true, None); }
        if let Some((a,b)) = ps.split_once('-') { if let (Ok(x),Ok(y))=(a.parse(),b.parse()) { return (false, Some((x,y))); } }
        if let Ok(x) = ps.parse::<u16>() { return (false, Some((x,x))); }
    }
    (false, None)
}

fn parse_cidr(host: &str) -> Option<(std::net::IpAddr, u8)> {
    if let Some((ip, pre)) = host.split_once('/') {
        if let (Ok(addr), Ok(p)) = (ip.parse::<std::net::IpAddr>(), pre.parse::<u8>()) { return Some((addr, p)); }
    }
    None
}

fn ip_in_cidr(ip: std::net::IpAddr, cidr: (std::net::IpAddr, u8)) -> bool {
    match (ip, cidr.0) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
            let a = u32::from(a); let n = u32::from(n);
            let p = cidr.1; if p==0 { return true; }
            let mask = if p==32 { u32::MAX } else { (!0u32) << (32 - p as u32) };
            (a & mask) == (n & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
            let a = u128::from(a); let n = u128::from(n);
            let p = cidr.1; if p==0 { return true; }
            let mask: u128 = if p==128 { u128::MAX } else { (!0u128) << (128 - p as u32) };
            (a & mask) == (n & mask)
        }
        _ => false,
    }
}

fn allowed_match(host: &str, port: Option<&str>, allow: &str) -> bool {
    // CIDR
    if let Some((net, pre)) = parse_cidr(allow) {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if ip_in_cidr(ip, (net, pre)) { return true; }
        }
        return false;
    }
    // wildcard / exact host patterns with optional port or ranges
    let (a_host_port, a_ps) = hostport_parts(allow);
    let (any_port, range) = parse_port_spec(a_ps);
    let a_host = a_host_port.as_ref();
    if let Some(suf) = a_host.strip_prefix("*.") {
        if host.ends_with(suf) {
            if any_port { return true; }
            if let (Some((lo,hi)), Some(p)) = (range, port.and_then(|x| x.parse::<u16>().ok())) { return p>=lo && p<=hi; }
            return range.is_none();
        }
    }
    if a_host == host {
        if any_port { return true; }
        if let (Some((lo,hi)), Some(p)) = (range, port.and_then(|x| x.parse::<u16>().ok())) { return p>=lo && p<=hi; }
        return range.is_none();
    }
    // IPv6 literal allow entry without brackets
    if a_host.starts_with('[') && a_host.ends_with(']') {
        let inner = &a_host[1..a_host.len()-1];
        if inner == host { return true; }
    }
    false
}

// Very small YAML walker to extract capabilities.fs.allow path entries
fn load_fs_allow_from_policy(path: &str) -> Vec<String> {
    let text = match std::fs::read_to_string(path) { Ok(s) => s, Err(_) => return vec![] };
    let mut out = Vec::new();
    let mut in_caps = false;
    let mut in_fs = false;
    let mut in_allow = false;
    let mut caps_indent = 0usize;
    let mut fs_indent = 0usize;
    let mut allow_indent = 0usize;
    for raw in text.lines() {
        let indent = raw.chars().take_while(|c| c.is_whitespace()).count();
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        if !in_caps && line == "capabilities:" { in_caps = true; caps_indent = indent; continue; }
        if in_caps {
            if indent <= caps_indent { in_caps = false; in_fs = false; in_allow = false; }
            if !in_fs && line == "fs:" { in_fs = true; fs_indent = indent; continue; }
            if in_fs {
                if indent <= fs_indent { in_fs = false; in_allow = false; }
                if !in_allow && line == "allow:" { in_allow = true; allow_indent = indent; continue; }
                if in_allow {
                    if indent <= allow_indent { in_allow = false; }
                    if line.starts_with("- ") {
                        // expect '- path: "..."'
                        if let Some(rest) = line.trim_start_matches("- ").strip_prefix("path:") {
                            let v = rest.trim().trim_start_matches(':').trim().trim_matches('"');
                            if !v.is_empty() { out.push(v.to_string()); }
                        }
                    }
                }
            }
        }
    }
    out
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

    if args[0] == "consume" {
        // JetStream consumer mode (feature-gated)
        #[cfg(feature = "jet")]
        {
            let url = args
                .iter()
                .position(|a| a == "--url")
                .and_then(|i| args.get(i + 1).cloned())
                .unwrap_or_else(|| env::var("NATS_URL").unwrap_or_else(|_| "127.0.0.1:4222".to_string()));
            let subject = args
                .iter()
                .position(|a| a == "--subject")
                .and_then(|i| args.get(i + 1).cloned())
                .unwrap_or_else(|| env::var("NATS_REQ_SUBJ").unwrap_or_else(|_| "run.req.default".to_string()));
            if let Err(e) = consume_entry(&url, &subject) {
                eprintln!("consume error: {}", e);
                std::process::exit(4);
            }
            return;
        }
        #[cfg(not(feature = "jet"))]
        {
            eprintln!("jet feature not enabled");
            std::process::exit(4);
        }
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
        // JSON Schema validation against schemas/spell_request.schema.json
        let schema_path = Path::new("schemas/spell_request.schema.json");
        if schema_path.exists() {
            match std::fs::read_to_string(schema_path) {
                Ok(schema_txt) => {
                    let schema_json: serde_json::Value = serde_json::from_str(&schema_txt).unwrap_or(serde_json::json!({}));
                    if let Ok(compiled) = jsonschema::JSONSchema::options().compile(&schema_json) {
                        let result = compiled.validate(&req_val);
                        if let Err(errors) = result {
                            for err in errors {
                                eprintln!("schema: {}", err);
                            }
                            std::process::exit(1);
                        }
                    }
                }
                Err(_) => {}
            }
        }
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
    eprintln!("policy: using {} (wall_sec={}, cpu_ms={}, memory_mb={})", 
        &policy_path, limits.wall_sec, limits.cpu_ms, limits.memory_mb);
    // Enforce env allow/deny
    let (env_allow, env_deny) = load_env_policy_from_policy(&policy_path);
    for (k, _v) in &req.env { if env_deny.iter().any(|p| pat_matches(k, p)) { eprintln!("policy: env deny {}", k); std::process::exit(3); } }
    if !env_allow.is_empty() {
        for (k, _v) in &req.env { if !env_allow.iter().any(|p| pat_matches(k, p)) { eprintln!("policy: env not allowed {}", k); std::process::exit(3); } }
    }
    // Enforce NET allowlist: union of request.allow_net and policy capabilities.net.allow
    if net_intent {
        let mut allowed: Vec<String> = req.allow_net.clone();
        allowed.extend(load_net_allow_from_policy(&policy_path));
        let hosts = extract_http_hosts(&req.cmd);
        if allowed.is_empty() {
            eprintln!("policy: network is not allowed (no allowlist)");
            std::process::exit(3);
        }
        for h in hosts {
            let (h_host, h_port) = hostport_parts(&h);
            let ok = allowed.iter().any(|a| allowed_match(&h_host, h_port, a));
            if !ok {
                eprintln!("policy: network to {} not allowed", h);
                std::process::exit(3);
            }
        }
    }
    if req.timeout_sec > limits.wall_sec {
        eprintln!(
            "policy: timeout_sec {} exceeds wall_sec limit {}",
            req.timeout_sec, limits.wall_sec
        );
        std::process::exit(3);
    }

    if net_intent && req.allow_net.is_empty() && load_net_allow_from_policy(&policy_path).is_empty() {
        risk_score += 40;
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
        let fs_readonly = load_fs_readonly_from_policy(&policy_path);
        let policy_fs_allow = load_fs_allow_from_policy(&policy_path);
        for f in &req.files {
            let p = Path::new(&f.path);
            // Basic path sanity: must be absolute and no parent traversal
            if !p.is_absolute() || f.path.contains("..") {
                eprintln!("schema: file.path must be absolute and must not contain '..'");
                std::process::exit(1);
            }
            for ro in &fs_readonly { if pat_matches(&f.path, ro) { eprintln!("policy: write to readonly {}", f.path); std::process::exit(20); } }
            let allowed_tmp = p.starts_with("/tmp/");
            let mut allowed = allowed_tmp; // default allow only /tmp/**
            // Also allow paths granted by policy capabilities.fs.allow
            for pat in &policy_fs_allow {
                if pat == "/tmp/**" && allowed_tmp { allowed = true; break; }
                if pat == &f.path { allowed = true; break; }
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
        let sb = detect_sandbox();
        eprintln!("sandbox: {:?}", sb);
        match sb {
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
    // Output schema validation under --strict
    if strict {
        // Validate against schemas/spell_result.schema.json if present
        if Path::new("schemas/spell_result.schema.json").exists() {
            if let Ok(schema_txt) = std::fs::read_to_string("schemas/spell_result.schema.json") {
                if let Ok(schema_json) = serde_json::from_str::<serde_json::Value>(&schema_txt) {
                    if let Ok(compiled) = jsonschema::JSONSchema::options().compile(&schema_json) {
                        let out_val: serde_json::Value = serde_json::from_str(&out_json).unwrap();
                        let validation = compiled.validate(&out_val);
                        if let Err(errors) = validation {
                            for err in errors { eprintln!("output schema: {}", err); }
                            std::process::exit(2);
                        }
                    }
                }
            }
        }
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

#[cfg(feature = "jet")]
fn consume_entry(url: &str, subject: &str) -> anyhow::Result<()> {
    use futures_util::StreamExt;
    use std::collections::{HashSet, VecDeque};
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let nc = bootstrapped::jet::jet_impl::connect(&format!("nats://{}", url))
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        fn env_u64(key: &str, default: u64) -> u64 { std::env::var(key).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(default) }
        fn env_i64(key: &str, default: i64) -> i64 { std::env::var(key).ok().and_then(|s| s.parse::<i64>().ok()).unwrap_or(default) }
        use async_nats::jetstream::{self, stream::{Config, RetentionPolicy, StorageType}};
        let js = jetstream::new(nc.clone());
        // Ensure JetStream stream exists for dedupe window
        {
            let name = std::env::var("NATS_STREAM").unwrap_or_else(|_| "RUN".to_string());
            let dup_sec = env_u64("NATS_DUP_WINDOW_SEC", 120);
            let cfg = Config {
                name: name.clone(),
                subjects: vec![subject.to_string()],
                retention: RetentionPolicy::Limits,
                max_consumers: -1,
                max_messages: -1,
                max_bytes: -1,
                duplicate_window: std::time::Duration::from_secs(dup_sec),
                storage: StorageType::File,
                ..Default::default()
            };
            if js.get_stream(&name).await.is_err() {
                let _ = js.create_stream(cfg).await;
            }

            // Ensure a durable consumer exists
            use async_nats::jetstream::consumer::{self, pull};
            let durable = std::env::var("NATS_DURABLE").unwrap_or_else(|_| "RUN_WORKER".to_string());
            let max_ack_pending = std::env::var("NATS_MAX_ACK_PENDING").ok().and_then(|s| s.parse::<i64>().ok()).unwrap_or(2048);
            let ack_wait_sec = std::env::var("NATS_ACK_WAIT_SEC").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(30);
            let c_cfg = pull::Config {
                durable_name: Some(durable.clone()),
                ack_policy: consumer::AckPolicy::Explicit,
                max_ack_pending,
                ack_wait: std::time::Duration::from_secs(ack_wait_sec),
                ..Default::default()
            };
            if let Ok(stream) = js.get_stream(&name).await {
                if stream.get_consumer::<pull::Config>(&durable).await.is_err() {
                    let _ = stream.create_consumer(c_cfg.clone()).await;
                }
                // Optional: override max_deliver via env by creating a generic consumer config
                if let Ok(max_deliver) = std::env::var("NATS_CONSUMER_MAX_DELIVER").ok().and_then(|s| s.parse::<i64>().ok()) {
                    let base = async_nats::jetstream::consumer::Config { durable_name: Some(durable.clone()), max_deliver, ..Default::default() };
                    let _ = stream.create_consumer(base).await;
                }
                // Switch to JetStream pull consumption
                let consumer = stream.get_consumer::<pull::Config>(&durable).await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let mut messages = consumer.messages().await.map_err(|e| anyhow::anyhow!(e.to_string()))?;

                // Dedupe caches and simple metrics
                let mut seen: HashSet<String> = HashSet::new();
                let mut order: VecDeque<String> = VecDeque::new();
                let dedupe_max = std::env::var("MAGICRUNE_DEDUPE_MAX").ok().and_then(|s| s.parse::<usize>().ok()).unwrap_or(1024);
                let metrics_every = env_u64("MAGICRUNE_METRICS_EVERY", 100);
                let mut count_total: u64 = 0;
                let mut count_dupe: u64 = 0;
                let mut count_red: u64 = 0;
                let metrics_text = std::env::var("MAGICRUNE_METRICS_TEXTFILE").ok();
                fn write_text_metrics(path:&str,total:u64,dupe:u64,red:u64,prefix:&str){
                    use std::io::Write; let tmp=format!("{}.tmp",path);
                    if let Ok(mut f)=std::fs::File::create(&tmp){
                        let _=writeln!(f,"# magicrune metrics");
                        let _=writeln!(f,"{}_processed_total {}",prefix,total);
                        let _=writeln!(f,"{}_dupe_total {}",prefix,dupe);
                        let _=writeln!(f,"{}_red_total {}",prefix,red);
                    }
                    let _=std::fs::rename(tmp,path);
                }
                // Jitter helpers (e.g., "200..=800")
                fn parse_jitter(spec: &str) -> Option<(u64,u64)> {
                    let s = spec.trim();
                    if let Some((a,b)) = s.split_once("..=") {
                        if let (Ok(lo), Ok(hi)) = (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
                            if lo <= hi { return Some((lo,hi)); }
                        }
                    } else if let Some((a,b)) = s.split_once("..") {
                        if let (Ok(lo), Ok(hi)) = (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
                            if lo <= hi { return Some((lo,hi)); }
                        }
                    }
                    None
                }
                fn jitter_ms(r: Option<(u64,u64)>) -> u64 {
                    if let Some((lo,hi)) = r {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos();
                        let mut x = (now as u64).wrapping_mul(6364136223846793005).wrapping_add(1);
                        x ^= x >> 33; x = x.wrapping_mul(0xff51afd7ed558ccd); x ^= x >> 33;
                        let span = hi - lo + 1;
                        return lo + (x % span);
                    }
                    0
                }
                let jitter = std::env::var("MAGICRUNE_TEST_DELAY_MS_JITTER").ok().and_then(|s| parse_jitter(&s));
                let skip_ack_once = std::env::var("MAGICRUNE_TEST_SKIP_ACK_ONCE").ok().as_deref() == Some("1");
                let mut skipped_once: std::collections::HashSet<String> = std::collections::HashSet::new();
                let metrics_file = std::env::var("MAGICRUNE_METRICS_FILE").ok();

                let delay_ms = env_u64("MAGICRUNE_TEST_DELAY_MS", 0);
                while let Some(Ok(msg)) = messages.next().await {
                    count_total += 1;
                    let id = msg.headers.as_ref().and_then(|h| h.get("Nats-Msg-Id")).map(|v| v.to_string()).unwrap_or_else(|| bootstrapped::jet::compute_msg_id(msg.payload.as_ref()));
                    if seen.contains(&id) { count_dupe += 1; let _ = msg.ack().await; continue; }
                    if seen.insert(id.clone()) { order.push_back(id); if order.len() > dedupe_max { if let Some(old)=order.pop_front(){ seen.remove(&old);} } }

                    let payload = msg.payload.to_vec();
                    let req_val: serde_json::Value = match serde_json::from_slice(&payload) { Ok(v) => v, Err(_) => { let _=msg.ack().await; continue; } };
                    let mut seed_le = 0u64.to_le_bytes().to_vec();
                    if let Some(s) = req_val.get("seed").and_then(|x| x.as_u64()) { seed_le = s.to_le_bytes().to_vec(); }
                    let mut all = payload.clone(); all.extend_from_slice(&seed_le);
                    let run_id = format!("r_{}", sha256_hex(&all));

                    let req: SpellRequest = match serde_json::from_slice(&payload) { Ok(r) => r, Err(_) => { let _=msg.ack().await; continue; } };

                    // Minimal grading and policy
                    let cmd_l = req.cmd.to_lowercase();
                    let mut risk_score: u32 = 0;
                    let net_intent = cmd_l.contains("curl ") || cmd_l.contains("wget ") || cmd_l.contains("http://") || cmd_l.contains("https://");
                    let policy_path = std::env::var("MAGICRUNE_POLICY").unwrap_or_else(|_| "policies/default.policy.yml".to_string());
                    let limits = load_limits_from_policy(&policy_path);
                    if net_intent && req.allow_net.is_empty() {
                        let res = SpellResult { run_id: run_id.clone(), verdict: "red".into(), risk_score: 80, exit_code: 20, duration_ms: 0, stdout_trunc: false, sbom_attestation: None };
                        let subj = format!("run.res.{}", run_id);
                    let total_delay = delay_ms + jitter_ms(jitter);
                    if total_delay > 0 { tokio::time::sleep(std::time::Duration::from_millis(total_delay)).await; }
                    let _ = js.publish(subj, serde_json::to_vec(&res)?.into()).await;
                        count_red += 1;
                        if !(skip_ack_once && skipped_once.insert(run_id.clone())) { let _ = msg.ack().await; }
                    if let Some(path) = &metrics_file { let _ = std::fs::write(path, format!("{{\"total\":{},\"dupe\":{},\"red\":{}}}", count_total, count_dupe, count_red)); }
                    if let Some(p) = &metrics_text { write_text_metrics(p, count_total, count_dupe, count_red, "magicrune"); }
                    continue;
                }
                    if cmd_l.contains("ssh ") { risk_score += 30; }

                    // Files
                    let mut fs_violation = false;
                    for f in &req.files {
                        let p = std::path::Path::new(&f.path);
                        if !p.is_absolute() || f.path.contains("..") { fs_violation = true; break; }
                        let allowed_tmp = p.starts_with("/tmp/");
                        let mut allowed = allowed_tmp;
                        if !req.allow_fs.is_empty() { for pat in &req.allow_fs { if pat=="/tmp/**" && allowed_tmp { allowed = true; break; } if pat==&f.path { allowed = true; break; } } }
                        if !allowed { fs_violation = true; break; }
                        if let Some(dir) = p.parent() { let _ = std::fs::create_dir_all(dir); }
                        if !f.content_b64.is_empty() { if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&f.content_b64) { let _ = std::fs::write(p, &bytes); } } else { let _ = std::fs::write(p, []); }
                    }
                    if fs_violation {
                        let res = SpellResult { run_id: run_id.clone(), verdict: "red".into(), risk_score: risk_score.max(80), exit_code: 20, duration_ms: 0, stdout_trunc: false, sbom_attestation: None };
                        let subj = format!("run.res.{}", run_id);
                        let total_delay = delay_ms + jitter_ms(jitter);
                        if total_delay > 0 { tokio::time::sleep(std::time::Duration::from_millis(total_delay)).await; }
                        let _ = js.publish(subj, serde_json::to_vec(&res)?.into()).await;
                        count_red += 1;
                        if !(skip_ack_once && skipped_once.insert(run_id.clone())) { let _ = msg.ack().await; }
                    if let Some(path) = &metrics_file { let _ = std::fs::write(path, format!("{{\"total\":{},\"dupe\":{},\"red\":{}}}", count_total, count_dupe, count_red)); }
                    if let Some(p) = &metrics_text { write_text_metrics(p, count_total, count_dupe, count_red, "magicrune"); }
                    continue;
                }

                    // Execute with wall timeout
                    let mut exit_code = 0i32; let mut duration_ms: u64 = 0;
                    if std::env::var("MAGICRUNE_DRY_RUN").ok().as_deref() != Some("1") && !req.cmd.trim().is_empty() {
                        let started = std::time::Instant::now();
                        let mut child = std::process::Command::new("bash").arg("-lc").arg(&req.cmd).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn()?;
                        if !req.stdin.is_empty() { if let Some(mut sin) = child.stdin.take() { use std::io::Write as _; let _ = sin.write_all(req.stdin.as_bytes()); } }
                        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(limits.wall_sec);
                        loop {
                            if let Ok(Some(status)) = child.try_wait() { let _ = child.wait_with_output(); duration_ms = started.elapsed().as_millis() as u64; if let Some(c) = status.code() { exit_code = c; } break; }
                            if std::time::Instant::now() >= deadline { let _ = child.kill(); duration_ms = started.elapsed().as_millis() as u64; exit_code = 20; break; }
                            std::thread::sleep(std::time::Duration::from_millis(25));
                        }
                    }

                    let thresholds = load_thresholds_from_policy(&policy_path);
                    let verdict = decide_verdict_from_thresholds(risk_score, &thresholds);
                    let res = SpellResult { run_id: run_id.clone(), verdict: verdict.to_string(), risk_score, exit_code, duration_ms, stdout_trunc: false, sbom_attestation: None };
                    let subj = format!("run.res.{}", run_id);
                    let total_delay = delay_ms + jitter_ms(jitter);
                    if total_delay > 0 { tokio::time::sleep(std::time::Duration::from_millis(total_delay)).await; }
                    let _ = js.publish(subj.clone(), serde_json::to_vec(&res)?.into()).await;
                    if !(skip_ack_once && skipped_once.insert(run_id.clone())) { let _ = msg.ack().await; }

                    let ack_subj = format!("run.ack.{}", run_id);
                    let mut ack = nc.subscribe(ack_subj).await?;
                    let ack_ack_wait = env_u64("ACK_ACK_WAIT_SEC", 2);
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(ack_ack_wait), ack.next()).await;
                    if let Some(path) = &metrics_file { let _ = std::fs::write(path, format!("{{\"total\":{},\"dupe\":{},\"red\":{}}}", count_total, count_dupe, count_red)); }
                    if let Some(p) = &metrics_text { write_text_metrics(p, count_total, count_dupe, count_red, "magicrune"); }
                    if metrics_every > 0 && count_total % metrics_every == 0 {
                        eprintln!("magicrune consume: processed={} dupes={} reds={}", count_total, count_dupe, count_red);
                    }
                }
                return Ok(());
            }
        }
        let mut sub = nc.subscribe(subject.to_string()).await?;

        let mut seen: HashSet<String> = HashSet::new();
        let mut order: VecDeque<String> = VecDeque::new();
        const DEDUPE_MAX: usize = 1024;

        while let Some(msg) = sub.next().await {
            let id = msg
                .headers
                .as_ref()
                .and_then(|h| h.get("Nats-Msg-Id"))
                .map(|v| v.to_string())
                .unwrap_or_else(|| bootstrapped::jet::compute_msg_id(&msg.payload));
            if seen.contains(&id) {
                continue;
            }
            if seen.insert(id.clone()) {
                order.push_back(id);
                if order.len() > DEDUPE_MAX {
                    if let Some(old) = order.pop_front() {
                        seen.remove(&old);
                    }
                }
            }

            let req_val: serde_json::Value = match serde_json::from_slice(&msg.payload) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut seed_le = 0u64.to_le_bytes().to_vec();
            if let Some(s) = req_val.get("seed").and_then(|x| x.as_u64()) {
                seed_le = s.to_le_bytes().to_vec();
            }
            let mut all = msg.payload.to_vec();
            all.extend_from_slice(&seed_le);
            let run_id = format!("r_{}", sha256_hex(&all));

            let req: SpellRequest = match serde_json::from_slice(&msg.payload) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Minimal grading and policy checks
            let cmd_l = req.cmd.to_lowercase();
            let mut risk_score: u32 = 0;
            let net_intent = cmd_l.contains("curl ")
                || cmd_l.contains("wget ")
                || cmd_l.contains("http://")
                || cmd_l.contains("https://");
            let policy_path = std::env::var("MAGICRUNE_POLICY")
                .unwrap_or_else(|_| "policies/default.policy.yml".to_string());
            let limits = load_limits_from_policy(&policy_path);
            if net_intent && req.allow_net.is_empty() {
                let res = SpellResult {
                    run_id: run_id.clone(),
                    verdict: "red".into(),
                    risk_score: 80,
                    exit_code: 20,
                    duration_ms: 0,
                    stdout_trunc: false,
                    sbom_attestation: None,
                };
                let subj = format!("run.res.{}", run_id);
                let _ = nc.publish(subj, serde_json::to_vec(&res)?.into()).await;
                continue;
            }
            if cmd_l.contains("ssh ") { risk_score += 30; }

            // Materialize files subject to allow_fs
            let mut fs_violation = false;
            for f in &req.files {
                let p = std::path::Path::new(&f.path);
                if !p.is_absolute() || f.path.contains("..") { fs_violation = true; break; }
                let allowed_tmp = p.starts_with("/tmp/");
                let mut allowed = allowed_tmp;
                if !req.allow_fs.is_empty() {
                    for pat in &req.allow_fs {
                        if pat == "/tmp/**" && allowed_tmp { allowed = true; break; }
                        if pat == &f.path { allowed = true; break; }
                    }
                }
                if !allowed { fs_violation = true; break; }
                if let Some(dir) = p.parent() { let _ = std::fs::create_dir_all(dir); }
                if !f.content_b64.is_empty() {
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&f.content_b64) {
                        let _ = std::fs::write(p, &bytes);
                    }
                } else { let _ = std::fs::write(p, []); }
            }
            if fs_violation {
                let res = SpellResult {
                    run_id: run_id.clone(), verdict: "red".into(), risk_score: risk_score.max(80),
                    exit_code: 20, duration_ms: 0, stdout_trunc: false, sbom_attestation: None,
                };
                let subj = format!("run.res.{}", run_id);
                let _ = nc.publish(subj, serde_json::to_vec(&res)?.into()).await;
                continue;
            }

            // Execute with wall timeout
            let mut exit_code = 0i32;
            let mut duration_ms: u64 = 0;
            if std::env::var("MAGICRUNE_DRY_RUN").ok().as_deref() != Some("1") && !req.cmd.trim().is_empty() {
                let started = std::time::Instant::now();
                let mut child = std::process::Command::new("bash")
                    .arg("-lc").arg(&req.cmd)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;
                if !req.stdin.is_empty() {
                    if let Some(mut sin) = child.stdin.take() {
                        use std::io::Write as _;
                        let _ = sin.write_all(req.stdin.as_bytes());
                    }
                }
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(limits.wall_sec);
                loop {
                    if let Ok(Some(status)) = child.try_wait() {
                        let _ = child.wait_with_output();
                        duration_ms = started.elapsed().as_millis() as u64;
                        if let Some(c) = status.code() { exit_code = c; }
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        duration_ms = started.elapsed().as_millis() as u64;
                        exit_code = 20; break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }

            // Verdict mapping
            let thresholds = load_thresholds_from_policy(&policy_path);
            let verdict = decide_verdict_from_thresholds(risk_score, &thresholds);
            let res = SpellResult { run_id: run_id.clone(), verdict: verdict.to_string(), risk_score, exit_code, duration_ms, stdout_trunc: false, sbom_attestation: None };
            let subj = format!("run.res.{}", run_id);
            let _ = nc.publish(subj.clone(), serde_json::to_vec(&res)?.into()).await;

            // ack-ack wait
            let ack_subj = format!("run.ack.{}", run_id);
            let mut ack = nc.subscribe(ack_subj).await?;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), ack.next()).await;
        }
        Ok(())
    })
}
// Minimal patterns: '*' wildcard, suffix '/**' for subtree
fn pat_matches(s: &str, pat: &str) -> bool {
    if pat == "*" { return true; }
    if let Some(base) = pat.strip_suffix("/**") { return s.starts_with(base); }
    if pat.starts_with('*') && pat.ends_with('*') {
        let needle = &pat[1..pat.len()-1];
        return s.contains(needle);
    }
    if pat.starts_with('*') { return s.ends_with(&pat[1..]); }
    if pat.ends_with('*') { return s.starts_with(&pat[..pat.len()-1]); }
    s == pat
}

fn load_fs_readonly_from_policy(path: &str) -> Vec<String> {
    let text = match std::fs::read_to_string(path) { Ok(s) => s, Err(_) => return vec![] };
    let mut out = Vec::new();
    let mut in_caps=false; let mut in_fs=false; let mut in_ro=false;
    let (mut ci, mut fi, mut ri) = (0usize,0usize,0usize);
    for raw in text.lines() {
        let indent = raw.chars().take_while(|c| c.is_whitespace()).count();
        let line = raw.trim(); if line.is_empty() || line.starts_with('#') { continue; }
        if !in_caps && line == "capabilities:" { in_caps=true; ci=indent; continue; }
        if in_caps {
            if indent <= ci { in_caps=false; in_fs=false; in_ro=false; }
            if !in_fs && line == "fs:" { in_fs=true; fi=indent; continue; }
            if in_fs {
                if indent <= fi { in_fs=false; in_ro=false; }
                if !in_ro && line == "readonly:" { in_ro=true; ri=indent; continue; }
                if in_ro {
                    if indent <= ri { in_ro=false; }
                    if line.starts_with("- ") {
                        let v = line.trim_start_matches("- ").trim().trim_matches('"');
                        if !v.is_empty() { out.push(v.to_string()); }
                    }
                }
            }
        }
    }
    out
}

fn load_env_policy_from_policy(path: &str) -> (Vec<String>, Vec<String>) {
    let text = match std::fs::read_to_string(path) { Ok(s) => s, Err(_) => return (vec![], vec![]) };
    let mut allow = Vec::new(); let mut deny = Vec::new();
    let mut in_caps=false; let mut in_env=false; let mut in_allow=false; let mut in_deny=false;
    let (mut ci, mut ei, mut ai, mut di) = (0usize,0usize,0usize,0usize);
    for raw in text.lines() {
        let indent = raw.chars().take_while(|c| c.is_whitespace()).count();
        let line = raw.trim(); if line.is_empty() || line.starts_with('#') { continue; }
        if !in_caps && line == "capabilities:" { in_caps=true; ci=indent; continue; }
        if in_caps {
            if indent <= ci { in_caps=false; in_env=false; in_allow=false; in_deny=false; }
            if !in_env && line == "env:" { in_env=true; ei=indent; continue; }
            if in_env {
                if indent <= ei { in_env=false; in_allow=false; in_deny=false; }
                if !in_allow && line == "allow:" { in_allow=true; ai=indent; continue; }
                if !in_deny && line == "deny:" { in_deny=true; di=indent; continue; }
                if in_allow {
                    if indent <= ai { in_allow=false; }
                    if line.starts_with("- ") { let v=line.trim_start_matches("- ").trim().trim_matches('"'); if !v.is_empty(){ allow.push(v.to_string()); } }
                }
                if in_deny {
                    if indent <= di { in_deny=false; }
                    if line.starts_with("- ") { let v=line.trim_start_matches("- ").trim().trim_matches('"'); if !v.is_empty(){ deny.push(v.to_string()); } }
                }
            }
        }
    }
    (allow,deny)
}
