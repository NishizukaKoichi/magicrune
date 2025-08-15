use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use bootstrapped::schema::{PolicyDoc, SpellRequest, SpellResult};
use bootstrapped::grader;

#[derive(Parser, Debug)]
#[command(name = "magicrune", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Exec {
        #[arg(short = 'f', long = "file")]
        file: PathBuf,
        #[arg(long = "policy")]
        policy: Option<PathBuf>,
        #[arg(long = "timeout")]
        timeout: Option<u64>,
        #[arg(long = "seed")]
        seed: Option<u64>,
        #[arg(long = "out")]
        out: Option<PathBuf>,
        #[arg(long = "strict")]
        strict: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Exec { file, policy, timeout, seed, out, strict } => {
            let started = Instant::now();
            let data = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => { eprintln!("error: failed to read {}: {e}", file.display()); std::process::exit(1); }
            };
            let mut req: SpellRequest = match serde_json::from_str(&data) {
                Ok(v) => v,
                Err(e) => { if strict { eprintln!("error: input schema mismatch: {e}"); std::process::exit(1); } else { SpellRequest::default() } }
            };
            if timeout.is_some() { req.timeout_sec = timeout; }
            if seed.is_some() { req.seed = seed; }

            let policy_path = policy.unwrap_or_else(|| PathBuf::from("policies/default.policy.yml"));
            let policy_doc: PolicyDoc = match fs::read_to_string(&policy_path)
                .ok()
                .and_then(|s| serde_yaml::from_str(&s).ok()) {
                Some(p) => p,
                None => PolicyDoc { version: 1, grading: None },
            };

            let outcome = grader::grade(&req, &policy_doc);

            // Deterministic run_id = sha256(request + seed)
            let mut hasher = Sha256::new();
            hasher.update(data.as_bytes());
            if let Some(sd) = req.seed { hasher.update(sd.to_le_bytes()); }
            let hash = hasher.finalize();
            let hexed = hex::encode(hash);
            let run_id = format!("r_{}", &hexed[..20]);

            let result = SpellResult {
                run_id,
                verdict: outcome.verdict.clone(),
                risk_score: outcome.risk_score,
                exit_code: match outcome.verdict.as_str() { "green" => 0, "yellow" => 10, "red" => 20, _ => 4 },
                duration_ms: started.elapsed().as_millis() as u64,
                stdout_trunc: false,
                sbom_attestation: "file://sbom.spdx.json.sig".to_string(),
            };

            let json_str = match serde_json::to_string_pretty(&result) { Ok(s) => s, Err(e) => { eprintln!("error: output schema mismatch: {e}"); std::process::exit(2); } };
            if let Some(outp) = out { if let Err(e) = fs::write(&outp, json_str.as_bytes()) { eprintln!("error: failed to write {}: {e}", outp.display()); std::process::exit(4); } } else { println!("{json_str}"); }

            if outcome.verdict == "red" {
                let _ = fs::create_dir_all("quarantine");
                let qp = format!("quarantine/result_{}.json", result.run_id);
                let _ = fs::write(qp, json_str);
            }

            std::process::exit(result.exit_code);
        }
    }
}
