mod grader;
mod ledger;
mod sandbox;
mod schema;

use anyhow::{Context, Result};
use async_nats::jetstream::{self, Message};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Instant;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::grader::{Grader, RuneSage};
use crate::ledger::{Ledger, LocalLedger};
use crate::sandbox::Sandbox;
use crate::schema::{Policy, SpellRequest, SpellResult, Verdict};

#[derive(Parser)]
#[command(name = "magicrune")]
#[command(about = "AI/external code execution sandbox", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Exec {
        #[arg(short, long, help = "Request JSON file")]
        file: PathBuf,
        
        #[arg(long, help = "Policy YAML file")]
        policy: Option<PathBuf>,
        
        #[arg(long, default_value = "15", help = "Timeout in seconds (max 60)")]
        timeout: u32,
        
        #[arg(long, help = "Random seed for deterministic execution")]
        _seed: Option<u64>,
        
        #[arg(long, help = "Output JSON file (default: stdout)")]
        out: Option<PathBuf>,
        
        #[arg(long, help = "Strict schema validation")]
        strict: bool,
    },
    
    Serve {
        #[arg(long, default_value = "nats://localhost:4222", help = "NATS server URL")]
        nats_url: String,
        
        #[arg(long, default_value = "magicrune.db", help = "Database file path")]
        db_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Exec { file, policy, timeout, _seed, out, strict } => {
            execute_cli(file, policy, timeout, _seed, out, strict).await
        }
        Commands::Serve { nats_url, db_path } => {
            serve_jetstream(nats_url, db_path).await
        }
    }
}

async fn execute_cli(
    file: PathBuf,
    policy_path: Option<PathBuf>,
    timeout: u32,
    _seed: Option<u64>,
    out: Option<PathBuf>,
    strict: bool,
) -> Result<()> {
    let timeout = timeout.min(60);
    
    let request_json = tokio::fs::read_to_string(&file)
        .await
        .context("Failed to read request file")?;
    
    let mut request: SpellRequest = serde_json::from_str(&request_json)
        .context("Failed to parse request JSON")?;
    
    request.timeout_sec = timeout;
    
    if strict {
        validate_request_schema(&request_json)?;
    }
    
    let policy = load_policy(policy_path).await?;
    
    if !check_policy(&request, &policy) {
        error!("Request violates policy constraints");
        std::process::exit(3);
    }
    
    let db_path = std::env::temp_dir().join("magicrune_cli.db");
    let ledger = LocalLedger::new(&db_path)?;
    
    let request_id = ledger.store_request(&request).await?;
    
    if let Some(existing_run_id) = ledger.check_duplicate(&request_id).await? {
        if let Some(result) = ledger.get_result(&existing_run_id).await? {
            info!("Found cached result for request");
            output_result(&result, out).await?;
            return Ok(());
        }
    }
    
    let sandbox = Sandbox::new().await?;
    let start_time = Instant::now();
    
    let sandbox_result = sandbox.execute(&request, &policy).await?;
    let duration_ms = start_time.elapsed().as_millis() as u64;
    
    let grader = Grader::new(policy);
    let (verdict, mut risk_score) = grader.evaluate(&sandbox_result.logs);
    
    risk_score = RuneSage::adjust_score(risk_score, &sandbox_result.logs);
    let final_verdict = if risk_score > 60 { Verdict::Red } else { verdict };
    
    let mut result = SpellResult::new(final_verdict, risk_score, sandbox_result.exit_code);
    result.duration_ms = duration_ms;
    result.stdout = sandbox_result.stdout;
    result.stderr = sandbox_result.stderr;
    result.stdout_trunc = sandbox_result.stdout_truncated;
    result.stderr_trunc = sandbox_result.stderr_truncated;
    result.logs = sandbox_result.logs;
    
    if final_verdict == Verdict::Red {
        quarantine_output(&result).await?;
        result.stdout = "[QUARANTINED]".to_string();
        result.stderr = "[QUARANTINED]".to_string();
    }
    
    ledger.store_result(&result).await?;
    
    output_result(&result, out).await?;
    
    let exit_code = match final_verdict {
        Verdict::Green => 0,
        Verdict::Yellow => 10,
        Verdict::Red => 20,
    };
    
    std::process::exit(exit_code);
}

async fn serve_jetstream(nats_url: String, db_path: PathBuf) -> Result<()> {
    info!("Starting JetStream service on {}", nats_url);
    
    let client = async_nats::connect(&nats_url).await?;
    let jetstream = jetstream::new(client);
    
    let ledger = LocalLedger::new(&db_path)?;
    
    let stream = jetstream
        .get_or_create_stream(jetstream::stream::Config {
            name: "MAGICRUNE".to_string(),
            subjects: vec!["run.req.*".to_string()],
            ..Default::default()
        })
        .await?;
    
    let consumer = stream
        .get_or_create_consumer("processor", jetstream::consumer::pull::Config {
            durable_name: Some("processor".to_string()),
            ..Default::default()
        })
        .await?;
    
    use futures_util::StreamExt;
    let mut messages = consumer.messages().await?;
    
    while let Some(msg) = messages.next().await {
        let msg = msg?;
        
        match process_jetstream_message(&msg, &ledger).await {
            Ok(result) => {
                let response_subject = format!("run.res.{}", result.run_id);
                let response_data = serde_json::to_vec(&result)?;
                
                jetstream
                    .publish(response_subject, response_data.into())
                    .await?;
                
                msg.ack().await.map_err(|e| anyhow::anyhow!("Failed to ack message: {}", e))?;
            }
            Err(e) => {
                error!("Failed to process message: {}", e);
                msg.ack_with(async_nats::jetstream::AckKind::Nak(None)).await
                    .map_err(|e| anyhow::anyhow!("Failed to nak message: {}", e))?;
            }
        }
    }
    
    Ok(())
}

async fn process_jetstream_message(
    msg: &Message,
    ledger: &impl Ledger,
) -> Result<SpellResult> {
    let request: SpellRequest = serde_json::from_slice(&msg.payload)?;
    let request_id = request.generate_id();
    
    if let Some(existing_run_id) = ledger.check_duplicate(&request_id).await? {
        if let Some(result) = ledger.get_result(&existing_run_id).await? {
            info!("Returning cached result for duplicate request");
            return Ok(result);
        }
    }
    
    ledger.store_request(&request).await?;
    
    let policy = load_policy(None).await?;
    
    if !check_policy(&request, &policy) {
        let mut result = SpellResult::new(Verdict::Red, 100, -1);
        result.stderr = "Request violates policy constraints".to_string();
        return Ok(result);
    }
    
    let sandbox = Sandbox::new().await?;
    let start_time = Instant::now();
    
    let sandbox_result = sandbox.execute(&request, &policy).await?;
    let duration_ms = start_time.elapsed().as_millis() as u64;
    
    let grader = Grader::new(policy);
    let (verdict, mut risk_score) = grader.evaluate(&sandbox_result.logs);
    
    risk_score = RuneSage::adjust_score(risk_score, &sandbox_result.logs);
    let final_verdict = if risk_score > 60 { Verdict::Red } else { verdict };
    
    let mut result = SpellResult::new(final_verdict, risk_score, sandbox_result.exit_code);
    result.duration_ms = duration_ms;
    result.stdout = sandbox_result.stdout;
    result.stderr = sandbox_result.stderr;
    result.stdout_trunc = sandbox_result.stdout_truncated;
    result.stderr_trunc = sandbox_result.stderr_truncated;
    result.logs = sandbox_result.logs;
    
    if final_verdict == Verdict::Red {
        quarantine_output(&result).await?;
        result.stdout = "[QUARANTINED]".to_string();
        result.stderr = "[QUARANTINED]".to_string();
    }
    
    ledger.store_result(&result).await?;
    
    Ok(result)
}

async fn load_policy(path: Option<PathBuf>) -> Result<Policy> {
    let policy_path = path.unwrap_or_else(|| PathBuf::from("policies/default.policy.yml"));
    
    if policy_path.exists() {
        let policy_yaml = tokio::fs::read_to_string(&policy_path)
            .await
            .context("Failed to read policy file")?;
        
        serde_yaml::from_str(&policy_yaml)
            .context("Failed to parse policy YAML")
    } else {
        Ok(default_policy())
    }
}

fn default_policy() -> Policy {
    Policy {
        version: 1,
        capabilities: schema::Capabilities {
            fs: schema::AccessPolicy {
                default: schema::AccessDefault::Deny,
                allow: vec!["/tmp/**".to_string()],
            },
            net: schema::AccessPolicy {
                default: schema::AccessDefault::Deny,
                allow: vec![],
            },
        },
        limits: schema::Limits {
            cpu_ms: 5000,
            memory_mb: 512,
            wall_sec: 15,
        },
        grading: schema::GradingConfig {
            thresholds: schema::Thresholds {
                green: "<=20".to_string(),
                yellow: "21..=60".to_string(),
                red: ">=61".to_string(),
            },
        },
    }
}

fn check_policy(request: &SpellRequest, policy: &Policy) -> bool {
    if request.timeout_sec > policy.limits.wall_sec {
        warn!("Request timeout exceeds policy limit");
        return false;
    }
    
    for path in &request.allow_fs {
        if !policy.capabilities.fs.allow.iter().any(|allowed| {
            path.starts_with(allowed.trim_end_matches("/**"))
        }) {
            warn!("Requested filesystem access not allowed: {}", path);
            return false;
        }
    }
    
    for host in &request.allow_net {
        if policy.capabilities.net.default == schema::AccessDefault::Deny
            && !policy.capabilities.net.allow.contains(host) {
            warn!("Requested network access not allowed: {}", host);
            return false;
        }
    }
    
    true
}

fn validate_request_schema(_json: &str) -> Result<()> {
    Ok(())
}

async fn output_result(result: &SpellResult, out: Option<PathBuf>) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    
    if let Some(path) = out {
        tokio::fs::write(path, json).await?;
    } else {
        println!("{}", json);
    }
    
    Ok(())
}

async fn quarantine_output(result: &SpellResult) -> Result<()> {
    let quarantine_dir = PathBuf::from("quarantine");
    tokio::fs::create_dir_all(&quarantine_dir).await?;
    
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let quarantine_file = quarantine_dir.join(format!("{}_{}.json", timestamp, result.run_id));
    
    let quarantine_data = serde_json::json!({
        "run_id": result.run_id,
        "risk_score": result.risk_score,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "logs": result.logs,
    });
    
    tokio::fs::write(quarantine_file, serde_json::to_string_pretty(&quarantine_data)?).await?;
    
    info!("Quarantined output for run {}", result.run_id);
    
    Ok(())
}