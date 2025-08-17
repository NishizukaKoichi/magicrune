#[cfg(feature = "jet")]
mod app {
    use base64::Engine;
    use bootstrapped::jet::{compute_msg_id, jet_impl};
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::str::FromStr;
    use std::time::{Duration, Instant};

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

    fn load_thresholds_from_policy(path: &str) -> (String, String, String) {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let green = extract_yaml_scalar(&text, "green").unwrap_or_else(|| "<=20".to_string());
        let yellow = extract_yaml_scalar(&text, "yellow").unwrap_or_else(|| "21..=60".to_string());
        let red = extract_yaml_scalar(&text, "red").unwrap_or_else(|| ">=61".to_string());
        (green, yellow, red)
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

    fn load_limits_from_policy(path: &str) -> (u64, u64, u64) {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let wall_sec = extract_yaml_u64(&text, "wall_sec").unwrap_or(60);
        let cpu_ms = extract_yaml_u64(&text, "cpu_ms").unwrap_or(5000);
        let memory_mb = extract_yaml_u64(&text, "memory_mb").unwrap_or(512);
        (wall_sec, cpu_ms, memory_mb)
    }

    fn decide(score: u32, green: &str, yellow: &str, red: &str) -> &'static str {
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
        let nc = jet_impl::connect(&format!("nats://{}", url)).await?;
        let mut sub = nc.subscribe(subject.clone()).await?;
        while let Some(msg) = sub.next().await {
            // Dedup id
            let _id = compute_msg_id(&msg.payload);
            // Parse request
            let req_val: serde_json::Value = match serde_json::from_slice(&msg.payload) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let req: SpellRequest = match serde_json::from_slice(&msg.payload) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Deterministic run_id (bytes + seed)
            let mut all = msg.payload.clone();
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
                // policy violation: respond red with exit=20
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
            let _ = nc.publish(subj, serde_json::to_vec(&res)?.into()).await;
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
