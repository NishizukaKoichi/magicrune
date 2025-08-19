#[cfg(feature = "jet")]
mod app {
    use base64::Engine;
    use bootstrapped::jet::{compute_msg_id, jet_impl};
    use futures_util::StreamExt;
    use serde::{Deserialize, Serialize};
    use std::collections::{HashSet, VecDeque};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    fn env_u64(key: &str, default: u64) -> u64 {
        std::env::var(key)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(default)
    }
    #[allow(dead_code)]
    fn env_i64(key: &str, default: i64) -> i64 {
        std::env::var(key)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(default)
    }

    #[derive(Debug, Deserialize)]
    struct SpellRequest {
        #[serde(default)]
        cmd: String,
        #[serde(default)]
        stdin: String,
        #[serde(default)]
        #[allow(dead_code)]
        env: serde_json::Map<String, serde_json::Value>,
        #[serde(default)]
        files: Vec<FileEntry>,
        #[serde(default)]
        #[allow(dead_code)]
        policy_id: String,
        #[serde(default)]
        #[allow(dead_code)]
        timeout_sec: u64,
        #[serde(default)]
        allow_net: Vec<String>,
        #[serde(default)]
        allow_fs: Vec<String>,
        #[serde(default)]
        seed: u64,
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

    fn sha256_hex(input: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input);
        let hash = hasher.finalize();
        format!("{:x}", hash)
    }

    fn load_net_allow_from_policy(path: &str) -> Vec<String> {
        let text = std::fs::read_to_string(path).unwrap_or_default();
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
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if !in_caps && line == "capabilities:" {
                in_caps = true;
                caps_indent = indent;
                continue;
            }
            if in_caps {
                if indent <= caps_indent {
                    in_caps = false;
                    in_net = false;
                    in_allow = false;
                }
                if !in_net && line == "net:" {
                    in_net = true;
                    net_indent = indent;
                    continue;
                }
                if in_net {
                    if indent <= net_indent {
                        in_net = false;
                        in_allow = false;
                    }
                    if !in_allow && line == "allow:" {
                        in_allow = true;
                        allow_indent = indent;
                        continue;
                    }
                    if in_allow {
                        if indent <= allow_indent {
                            in_allow = false;
                        }
                        if line.starts_with("- ") {
                            if let Some(rest) = line.trim_start_matches("- ").split_once(':') {
                                let v = rest.1.trim().trim_matches('"');
                                if !v.is_empty() {
                                    out.push(v.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }

    fn extract_http_hosts(cmd: &str) -> Vec<String> {
        let mut out = Vec::new();
        for scheme in ["http://", "https://"].iter() {
            let mut i = 0usize;
            while let Some(pos) = cmd[i..].find(scheme) {
                let start = i + pos + scheme.len();
                let rest = &cmd[start..];
                let end = rest
                    .find(|c: char| c == '/' || c.is_whitespace())
                    .unwrap_or(rest.len());
                let hostport = &rest[..end];
                if !hostport.is_empty() {
                    out.push(hostport.to_string());
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
                let after = &rest[pos + 1..];
                if let Some(p) = after.strip_prefix(':') {
                    return (std::borrow::Cow::Owned(host.to_string()), Some(p));
                }
                return (std::borrow::Cow::Owned(host.to_string()), None);
            }
        }
        if let Some((h, p)) = st.rsplit_once(':') {
            if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
                return (std::borrow::Cow::Owned(h.to_string()), Some(p));
            }
        }
        (std::borrow::Cow::Borrowed(st), None)
    }

    fn parse_port_spec(p: Option<&str>) -> (bool, Option<(u16, u16)>) {
        if let Some(ps) = p {
            if ps == "*" {
                return (true, None);
            }
            if let Some((a, b)) = ps.split_once('-') {
                if let (Ok(x), Ok(y)) = (a.parse(), b.parse()) {
                    return (false, Some((x, y)));
                }
            }
            if let Ok(x) = ps.parse::<u16>() {
                return (false, Some((x, x)));
            }
        }
        (false, None)
    }
    fn parse_cidr(host: &str) -> Option<(std::net::IpAddr, u8)> {
        if let Some((ip, pre)) = host.split_once('/') {
            if let (Ok(addr), Ok(p)) = (ip.parse(), pre.parse()) {
                return Some((addr, p));
            }
        }
        None
    }
    fn ip_in_cidr(ip: std::net::IpAddr, cidr: (std::net::IpAddr, u8)) -> bool {
        match (ip, cidr.0) {
            (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
                let a = u32::from(a);
                let n = u32::from(n);
                let p = cidr.1;
                if p == 0 {
                    return true;
                }
                let mask = if p == 32 {
                    u32::MAX
                } else {
                    (!0u32) << (32 - p as u32)
                };
                (a & mask) == (n & mask)
            }
            (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
                let a = u128::from(a);
                let n = u128::from(n);
                let p = cidr.1;
                if p == 0 {
                    return true;
                }
                let mask = if p == 128 {
                    u128::MAX
                } else {
                    (!0u128) << (128 - p as u32)
                };
                (a & mask) == (n & mask)
            }
            _ => false,
        }
    }
    fn allowed_match(host: &str, port: Option<&str>, allow: &str) -> bool {
        if let Some((net, pre)) = parse_cidr(allow) {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                return ip_in_cidr(ip, (net, pre));
            }
            return false;
        }
        let (a_host_port, a_ps) = hostport_parts(allow);
        let (any, range) = parse_port_spec(a_ps);
        let a_host = a_host_port.as_ref();
        if let Some(suf) = a_host.strip_prefix("*.") {
            if host.ends_with(suf) {
                if any {
                    return true;
                }
                if let (Some((lo, hi)), Some(p)) = (range, port.and_then(|x| x.parse::<u16>().ok()))
                {
                    return p >= lo && p <= hi;
                }
                return range.is_none();
            }
        }
        if a_host == host {
            if any {
                return true;
            }
            if let (Some((lo, hi)), Some(p)) = (range, port.and_then(|x| x.parse::<u16>().ok())) {
                return p >= lo && p <= hi;
            }
            return range.is_none();
        }
        if a_host.starts_with('[') && a_host.ends_with(']') {
            let inner = &a_host[1..a_host.len() - 1];
            if inner == host {
                return true;
            }
        }
        false
    }

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

    fn load_thresholds_from_policy(path: &str) -> (String, String, String) {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let green = extract_yaml_scalar_under(&text, "thresholds", "green")
            .or_else(|| extract_yaml_scalar_under(&text, "grading", "green"))
            .unwrap_or_else(|| "<=20".to_string());
        let yellow = extract_yaml_scalar_under(&text, "thresholds", "yellow")
            .or_else(|| extract_yaml_scalar_under(&text, "grading", "yellow"))
            .unwrap_or_else(|| "21..=60".to_string());
        let red = extract_yaml_scalar_under(&text, "thresholds", "red")
            .or_else(|| extract_yaml_scalar_under(&text, "grading", "red"))
            .unwrap_or_else(|| ">=61".to_string());
        (green, yellow, red)
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

    fn load_limits_from_policy(path: &str) -> (u64, u64, u64) {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let wall_sec = extract_yaml_u64_under(&text, "limits", "wall_sec").unwrap_or(60);
        let cpu_ms = extract_yaml_u64_under(&text, "limits", "cpu_ms").unwrap_or(5000);
        let memory_mb = extract_yaml_u64_under(&text, "limits", "memory_mb").unwrap_or(512);
        (wall_sec, cpu_ms, memory_mb)
    }

    fn decide(score: u32, green: &str, yellow: &str, _red: &str) -> &'static str {
        fn matches(expr: &str, n: u32) -> bool {
            if let Some(rest) = expr.trim().strip_prefix("<=") {
                return u32::from_str(rest.trim()).map(|v| n <= v).unwrap_or(false);
            }
            if let Some(rest) = expr.trim().strip_prefix(">=") {
                return u32::from_str(rest.trim()).map(|v| n >= v).unwrap_or(false);
            }
            if let Some((a, b)) = expr.split_once("..=") {
                if let (Ok(x), Ok(y)) = (u32::from_str(a.trim()), u32::from_str(b.trim())) {
                    return n >= x && n <= y;
                }
            }
            false
        }
        if matches(green, score) {
            "green"
        } else if matches(yellow, score) {
            "yellow"
        } else {
            "red"
        }
    }

    #[tokio::main]
    pub async fn main() -> anyhow::Result<()> {
        let url = std::env::var("NATS_URL").unwrap_or_else(|_| "127.0.0.1:4222".to_string());
        let subject =
            std::env::var("NATS_REQ_SUBJ").unwrap_or_else(|_| "run.req.default".to_string());
        let nc = jet_impl::connect(&format!("nats://{}", url))
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        // Ensure JetStream stream exists for dedupe window
        {
            use async_nats::jetstream::{
                self,
                stream::{Config, RetentionPolicy, StorageType},
            };
            let js = jetstream::new(nc.clone());
            let name = std::env::var("NATS_STREAM").unwrap_or_else(|_| "RUN".to_string());
            let dup_sec = env_u64("NATS_DUP_WINDOW_SEC", 120);
            let cfg = Config {
                name: name.clone(),
                subjects: vec![subject.clone()],
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

            // Ensure a durable consumer exists (server-side retention/positioning)
            use async_nats::jetstream::consumer::{self, pull};
            let durable =
                std::env::var("NATS_DURABLE").unwrap_or_else(|_| "RUN_WORKER".to_string());
            let max_ack_pending = env_i64("NATS_MAX_ACK_PENDING", 2048);
            let ack_wait_sec = env_u64("NATS_ACK_WAIT_SEC", 30);
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
                // Replace core subscription with JetStream pull consumer messages
                let consumer = stream
                    .get_consumer::<pull::Config>(&durable)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let mut messages = consumer
                    .messages()
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                // Dedupe caches and simple metrics
                let mut seen: HashSet<String> = HashSet::new();
                let mut order: VecDeque<String> = VecDeque::new();
                let dedupe_max = std::env::var("MAGICRUNE_DEDUPE_MAX")
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(1024);
                let metrics_every = env_u64("MAGICRUNE_METRICS_EVERY", 100);
                let mut count_total: u64 = 0;
                let mut count_dupe: u64 = 0;
                let mut count_red: u64 = 0;
                while let Some(Ok(msg)) = messages.next().await {
                    count_total += 1;
                    let id = msg
                        .headers
                        .as_ref()
                        .and_then(|h| h.get("Nats-Msg-Id"))
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| compute_msg_id(msg.payload.as_ref()));
                    if seen.contains(&id) {
                        count_dupe += 1;
                        let _ = msg.ack().await; // ack duplicates to advance
                        continue;
                    }
                    if seen.insert(id.clone()) {
                        order.push_back(id);
                        if order.len() > dedupe_max {
                            if let Some(old) = order.pop_front() {
                                seen.remove(&old);
                            }
                        }
                    }

                    // Reuse existing handling by synthesizing a core-like loop body
                    let payload = msg.payload.to_vec();
                    // Parse request
                    let _req_val: serde_json::Value = match serde_json::from_slice(&payload) {
                        Ok(v) => v,
                        Err(_) => {
                            let _ = msg.ack().await;
                            continue;
                        }
                    };
                    let req: SpellRequest = match serde_json::from_slice(&payload) {
                        Ok(r) => r,
                        Err(_) => {
                            let _ = msg.ack().await;
                            continue;
                        }
                    };

                    // Deterministic run_id (bytes + seed)
                    let mut all = payload.clone();
                    all.extend_from_slice(&req.seed.to_le_bytes());
                    let run_id = format!("r_{}", sha256_hex(&all));

                    // Minimal grading & policy
                    let cmd_l = req.cmd.to_lowercase();
                    let mut risk_score: u32 = 0;
                    let net_intent = cmd_l.contains("curl ")
                        || cmd_l.contains("wget ")
                        || cmd_l.contains("http://")
                        || cmd_l.contains("https://");
                    let policy_path = std::env::var("MAGICRUNE_POLICY")
                        .unwrap_or_else(|_| "policies/default.policy.yml".to_string());
                    let (wall_sec, _cpu_ms, _memory_mb) = load_limits_from_policy(&policy_path);
                    let policy_fs_allow = {
                        fn load_fs_allow_from_policy(text: &str) -> Vec<String> {
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
                                if line.starts_with('#') || line.is_empty() {
                                    continue;
                                }
                                if !in_caps && line == "capabilities:" {
                                    in_caps = true;
                                    caps_indent = indent;
                                    continue;
                                }
                                if in_caps {
                                    if indent <= caps_indent {
                                        in_caps = false;
                                        in_fs = false;
                                        in_allow = false;
                                    }
                                    if !in_fs && line == "fs:" {
                                        in_fs = true;
                                        fs_indent = indent;
                                        continue;
                                    }
                                    if in_fs {
                                        if indent <= fs_indent {
                                            in_fs = false;
                                            in_allow = false;
                                        }
                                        if !in_allow && line == "allow:" {
                                            in_allow = true;
                                            allow_indent = indent;
                                            continue;
                                        }
                                        if in_allow {
                                            if indent <= allow_indent {
                                                in_allow = false;
                                            }
                                            if line.starts_with("- ") {
                                                if let Some(rest) = line
                                                    .trim_start_matches("- ")
                                                    .strip_prefix("path:")
                                                {
                                                    let v = rest
                                                        .trim()
                                                        .trim_start_matches(':')
                                                        .trim()
                                                        .trim_matches('"');
                                                    if !v.is_empty() {
                                                        out.push(v.to_string());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            out
                        }
                        let txt = std::fs::read_to_string(&policy_path).unwrap_or_default();
                        load_fs_allow_from_policy(&txt)
                    };
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
                        let _ = js.publish(subj, serde_json::to_vec(&res)?.into()).await;
                        count_red += 1;
                        let _ = msg.ack().await;
                        continue;
                    }
                    if cmd_l.contains("ssh ") {
                        risk_score += 30;
                    }

                    // Files
                    let mut fs_violation = false;
                    for f in &req.files {
                        let p = Path::new(&f.path);
                        if !p.is_absolute() || f.path.contains("..") {
                            fs_violation = true;
                            break;
                        }
                        let allowed_tmp = p.starts_with("/tmp/");
                        let mut allowed = allowed_tmp;
                        for pat in &policy_fs_allow {
                            if pat == "/tmp/**" && allowed_tmp {
                                allowed = true;
                                break;
                            }
                            if pat == &f.path {
                                allowed = true;
                                break;
                            }
                        }
                        if !allowed {
                            fs_violation = true;
                            break;
                        }
                        if let Some(dir) = p.parent() {
                            let _ = std::fs::create_dir_all(dir);
                        }
                        if !f.content_b64.is_empty() {
                            if let Ok(bytes) =
                                base64::engine::general_purpose::STANDARD.decode(&f.content_b64)
                            {
                                let _ = std::fs::write(p, &bytes);
                            }
                        } else {
                            let _ = std::fs::write(p, []);
                        }
                    }
                    if fs_violation {
                        let res = SpellResult {
                            run_id: run_id.clone(),
                            verdict: "red".into(),
                            risk_score: risk_score.max(80),
                            exit_code: 20,
                            duration_ms: 0,
                            stdout_trunc: false,
                            sbom_attestation: None,
                        };
                        let subj = format!("run.res.{}", run_id);
                        let _ = js.publish(subj, serde_json::to_vec(&res)?.into()).await;
                        count_red += 1;
                        let _ = msg.ack().await;
                        continue;
                    }

                    // Execute
                    let mut duration_ms: u64 = 0;
                    let mut exit_code = 0i32;
                    if std::env::var("MAGICRUNE_DRY_RUN").ok().as_deref() != Some("1")
                        && !req.cmd.trim().is_empty()
                    {
                        let started = Instant::now();
                        let mut child = Command::new("bash")
                            .arg("-lc")
                            .arg(&req.cmd)
                            .stdin(Stdio::piped())
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped())
                            .spawn()?;
                        if !req.stdin.is_empty() {
                            if let Some(mut sin) = child.stdin.take() {
                                use std::io::Write as _;
                                let _ = sin.write_all(req.stdin.as_bytes());
                            }
                        }
                        let deadline = Instant::now() + Duration::from_secs(wall_sec);
                        loop {
                            if let Ok(Some(status)) = child.try_wait() {
                                let _ = child.wait_with_output();
                                duration_ms = started.elapsed().as_millis() as u64;
                                if let Some(c) = status.code() {
                                    exit_code = c;
                                }
                                break;
                            }
                            if Instant::now() >= deadline {
                                let _ = child.kill();
                                duration_ms = started.elapsed().as_millis() as u64;
                                exit_code = 20;
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(25));
                        }
                    }

                    // Respond + ack
                    let (green, yellow, red) = load_thresholds_from_policy(&policy_path);
                    let verdict = decide(risk_score, &green, &yellow, &red);
                    let res = SpellResult {
                        run_id: run_id.clone(),
                        verdict: verdict.to_string(),
                        risk_score,
                        exit_code,
                        duration_ms,
                        stdout_trunc: false,
                        sbom_attestation: None,
                    };
                    let subj = format!("run.res.{}", run_id);
                    let _ = js
                        .publish(subj.clone(), serde_json::to_vec(&res)?.into())
                        .await;
                    let _ = msg.ack().await;

                    // ack-ack wait
                    let ack_subj = format!("run.ack.{}", run_id);
                    let mut ack = nc.subscribe(ack_subj).await?;
                    let ack_ack_wait = env_u64("ACK_ACK_WAIT_SEC", 2);
                    let _ =
                        tokio::time::timeout(Duration::from_secs(ack_ack_wait), ack.next()).await;

                    if metrics_every > 0 && count_total % metrics_every == 0 {
                        eprintln!(
                            "js_consumer: processed={} dupes={} reds={}",
                            count_total, count_dupe, count_red
                        );
                    }
                }
                return Ok(());
            }
        }
        // Fallback to core subscription if JetStream setup failed
        let mut sub = nc.subscribe(subject.clone()).await?;
        let mut seen: HashSet<String> = HashSet::new();
        let mut order: VecDeque<String> = VecDeque::new();
        const DEDUPE_MAX: usize = 1024;
        while let Some(msg) = sub.next().await {
            let id = msg
                .headers
                .as_ref()
                .and_then(|h| h.get("Nats-Msg-Id"))
                .map(|v| v.to_string())
                .unwrap_or_else(|| compute_msg_id(&msg.payload));
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
            // Parse request
            let _req_val: serde_json::Value = match serde_json::from_slice(&msg.payload) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let req: SpellRequest = match serde_json::from_slice(&msg.payload) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Deterministic run_id (bytes + seed)
            let mut all = msg.payload.to_vec();
            all.extend_from_slice(&req.seed.to_le_bytes());
            let run_id = format!("r_{}", sha256_hex(&all));

            // Minimal grading
            let cmd_l = req.cmd.to_lowercase();
            let mut risk_score: u32 = 0;
            let net_intent = cmd_l.contains("curl ")
                || cmd_l.contains("wget ")
                || cmd_l.contains("http://")
                || cmd_l.contains("https://");
            let policy_path = std::env::var("MAGICRUNE_POLICY")
                .unwrap_or_else(|_| "policies/default.policy.yml".to_string());
            let (wall_sec, _cpu_ms, _memory_mb) = load_limits_from_policy(&policy_path);
            if net_intent && req.allow_net.is_empty() {
                // Enforce allowlist from policy + request
                let mut allow = req.allow_net.clone();
                allow.extend(load_net_allow_from_policy(&policy_path));
                let hosts = extract_http_hosts(&req.cmd);
                if allow.is_empty() {
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
                let mut violation = false;
                for h in hosts {
                    let (hh, hp) = hostport_parts(&h);
                    if !allow.iter().any(|a| allowed_match(&hh, hp, a)) {
                        violation = true;
                        break;
                    }
                }
                if violation {
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
            }
            if cmd_l.contains("ssh ") {
                risk_score += 30;
            }

            let (g, y, r) = load_thresholds_from_policy(&policy_path);
            let verdict = decide(risk_score, &g, &y, &r);
            let mut exit_code = match verdict {
                "green" => 0,
                "yellow" => 10,
                _ => 20,
            };

            // File materialization under policy allow_fs
            let mut fs_violation = false;
            for f in &req.files {
                let p = Path::new(&f.path);
                let allowed_tmp = p.starts_with("/tmp/");
                let mut allowed = allowed_tmp;
                if !req.allow_fs.is_empty() {
                    for pat in &req.allow_fs {
                        if pat == "/tmp/**" && allowed_tmp {
                            allowed = true;
                            break;
                        }
                        if pat == &f.path {
                            allowed = true;
                            break;
                        }
                    }
                }
                if !allowed {
                    fs_violation = true;
                    break;
                }
                if let Some(dir) = p.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if !f.content_b64.is_empty() {
                    if let Ok(bytes) =
                        base64::engine::general_purpose::STANDARD.decode(&f.content_b64)
                    {
                        let _ = std::fs::write(p, &bytes);
                    }
                } else {
                    let _ = std::fs::write(p, []);
                }
            }
            if fs_violation {
                let res = SpellResult {
                    run_id: run_id.clone(),
                    verdict: "red".into(),
                    risk_score: risk_score.max(80),
                    exit_code: 20,
                    duration_ms: 0,
                    stdout_trunc: false,
                    sbom_attestation: None,
                };
                let subj = format!("run.res.{}", run_id);
                let _ = nc.publish(subj, serde_json::to_vec(&res)?.into()).await;
                continue;
            }

            // Execute once with simple wall timeout
            let mut duration_ms: u64 = 0;
            if std::env::var("MAGICRUNE_DRY_RUN").ok().as_deref() != Some("1")
                && !req.cmd.trim().is_empty()
            {
                let started = Instant::now();
                let mut child = Command::new("bash")
                    .arg("-lc")
                    .arg(&req.cmd)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                if !req.stdin.is_empty() {
                    use std::io::Write as _;
                    if let Some(mut sin) = child.stdin.take() {
                        let _ = sin.write_all(req.stdin.as_bytes());
                    }
                }
                let deadline = Instant::now() + Duration::from_secs(wall_sec);
                loop {
                    if let Ok(Some(status)) = child.try_wait() {
                        let _ = child.wait_with_output();
                        duration_ms = started.elapsed().as_millis() as u64;
                        if let Some(c) = status.code() {
                            exit_code = c;
                        }
                        break;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        duration_ms = started.elapsed().as_millis() as u64;
                        exit_code = 20; // force red on timeout
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }

            let res = SpellResult {
                run_id: run_id.clone(),
                verdict: verdict.into(),
                risk_score,
                exit_code,
                duration_ms,
                stdout_trunc: false,
                sbom_attestation: None,
            };
            let subj = format!("run.res.{}", run_id);
            let _ = nc
                .publish(subj.clone(), serde_json::to_vec(&res)?.into())
                .await;

            // Wait for ack-ack style confirmation from publisher
            let ack_subj = format!("run.ack.{}", run_id);
            let mut ack = nc.subscribe(ack_subj.clone()).await?;
            let _ = tokio::time::timeout(Duration::from_secs(2), ack.next()).await;
        }
        Ok(())
    }
}

#[cfg(feature = "jet")]
fn main() {
    app::main().unwrap();
}

#[cfg(not(feature = "jet"))]
fn main() {
    eprintln!("jet feature not enabled");
}
