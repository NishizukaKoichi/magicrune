use anyhow::{Context, Result};
use async_nats::jetstream;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tokio_stream::StreamExt;

mod grader;
mod ledger;
mod sandbox;
mod schema;

use grader::Grader;
use ledger::{Ledger, LocalLedger};
use sandbox::{quarantine_output, Sandbox};
use schema::*;

#[derive(Parser)]
#[command(name = "magicrune")]
#[command(about = "Execute code safely in sandboxed environments")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Exec {
        #[arg(short, long, value_name = "FILE")]
        file: PathBuf,
        
        #[arg(long, default_value = "policies/default.policy.yml")]
        policy: PathBuf,
        
        #[arg(long, default_value = "15")]
        timeout: u32,
        
        #[arg(long)]
        seed: Option<u64>,
        
        #[arg(long)]
        out: Option<PathBuf>,
        
        #[arg(long)]
        strict: bool,
    },
    
    Serve {
        #[arg(long, default_value = "nats://localhost:4222")]
        nats_url: String,
        
        #[arg(long, default_value = "magicrune.db")]
        db_path: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .init();

    let cli = Cli::parse();
    
    match cli.command {
        Commands::Exec { 
            file, 
            policy, 
            timeout,
            seed,
            out,
            strict,
        } => {
            execute_cli(file, policy, timeout, seed, out, strict).await
        }
        Commands::Serve { nats_url, db_path } => {
            serve_jetstream(nats_url, db_path).await
        }
    }
}

async fn execute_cli(
    request_file: PathBuf,
    policy_file: PathBuf,
    timeout: u32,
    _seed: Option<u64>,
    out_file: Option<PathBuf>,
    strict: bool,
) -> Result<()> {
    let request_json = fs::read_to_string(&request_file)
        .context("Failed to read request file")?;
    
    let mut request: SpellRequest = serde_json::from_str(&request_json)
        .context("Failed to parse request JSON")?;
    
    if timeout > 0 {
        request.timeout_sec = timeout;
    }
    
    if let Err(e) = validate_request(&request) {
        error!("Invalid request: {}", e);
        process::exit(1);
    }
    
    let policy_yaml = fs::read_to_string(&policy_file)
        .context("Failed to read policy file")?;
    
    let policy: Policy = serde_yaml::from_str(&policy_yaml)
        .context("Failed to parse policy YAML")?;
    
    let ledger = LocalLedger::new("magicrune.db")?;
    
    let result = execute_spell(&request, &policy, &ledger).await?;
    
    let result_json = serde_json::to_string_pretty(&result)?;
    
    if let Some(out_path) = out_file {
        fs::write(&out_path, &result_json)
            .context("Failed to write result file")?;
        info!("Result written to: {}", out_path.display());
    } else {
        println!("{}", result_json);
    }
    
    if strict {
        if let Err(e) = validate_result(&result) {
            error!("Invalid result: {}", e);
            process::exit(2);
        }
    }
    
    let exit_code = match result.verdict {
        Verdict::Green => 0,
        Verdict::Yellow => 10,
        Verdict::Red => 20,
    };
    
    process::exit(exit_code);
}

async fn serve_jetstream(nats_url: String, db_path: String) -> Result<()> {
    info!("Connecting to NATS at {}", nats_url);
    
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
        .get_or_create_consumer("magicrune-worker", jetstream::consumer::pull::Config {
            durable_name: Some("magicrune-worker".to_string()),
            ..Default::default()
        })
        .await?;
    
    info!("JetStream consumer started");
    
    loop {
        match consumer.messages().await {
            Ok(mut stream) => {
                while let Some(Ok(msg)) = stream.next().await {
                    match process_jetstream_message(&msg, &ledger).await {
                        Ok(result) => {
                            let response_subject = format!("run.res.{}", result.run_id);
                            let response_data = serde_json::to_vec(&result)?;
                            
                            jetstream
                                .publish(response_subject, response_data.into())
                                .await?;
                            
                            msg.ack().await.ok();
                            info!("Processed run_id: {}", result.run_id);
                        }
                        Err(e) => {
                            error!("Failed to process message: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to get messages: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

async fn process_jetstream_message(
    msg: &async_nats::jetstream::Message,
    ledger: &LocalLedger,
) -> Result<SpellResult> {
    let request: SpellRequest = serde_json::from_slice(&msg.payload)?;
    
    validate_request(&request)?;
    
    let policy_path = format!("policies/{}.policy.yml", request.policy_id);
    let policy_yaml = fs::read_to_string(&policy_path)
        .unwrap_or_else(|_| fs::read_to_string("policies/default.policy.yml").unwrap());
    
    let policy: Policy = serde_yaml::from_str(&policy_yaml)?;
    
    execute_spell(&request, &policy, ledger).await
}

async fn execute_spell(
    request: &SpellRequest,
    policy: &Policy,
    ledger: &dyn Ledger,
) -> Result<SpellResult> {
    let run_id = generate_run_id();
    info!("Starting execution: {}", run_id);
    
    let sandbox = Sandbox::new(policy.clone())?;
    let grader = Grader::new(policy.clone());
    
    match sandbox.execute(request).await {
        Ok(sandbox_result) => {
            let combined_output = format!("{}\n{}", sandbox_result.stdout, sandbox_result.stderr);
            let (verdict, risk_score) = grader.grade(&sandbox_result.events, &combined_output);
            
            let mut result = SpellResult {
                run_id: run_id.clone(),
                verdict,
                risk_score,
                exit_code: sandbox_result.exit_code,
                duration_ms: sandbox_result.duration_ms,
                stdout: Some(sandbox_result.stdout.clone()),
                stderr: Some(sandbox_result.stderr.clone()),
                stdout_trunc: sandbox_result.stdout_truncated,
                stderr_trunc: sandbox_result.stderr_truncated,
                sbom_attestation: None,
                error: None,
                quarantine_path: None,
            };
            
            if verdict == Verdict::Red {
                warn!("Red verdict for run_id: {} (score: {})", run_id, risk_score);
                let quarantine_path = quarantine_output(
                    &run_id,
                    &sandbox_result.stdout,
                    &sandbox_result.stderr
                ).await?;
                result.quarantine_path = Some(quarantine_path);
                result.stdout = Some("[QUARANTINED]".to_string());
                result.stderr = Some("[QUARANTINED]".to_string());
            }
            
            ledger.record_run(request, &result).await?;
            Ok(result)
        }
        Err(e) => {
            error!("Sandbox execution failed: {}", e);
            let result = SpellResult {
                run_id,
                verdict: Verdict::Red,
                risk_score: 100,
                exit_code: -1,
                duration_ms: 0,
                stdout: None,
                stderr: None,
                stdout_trunc: false,
                stderr_trunc: false,
                sbom_attestation: None,
                error: Some(e.to_string()),
                quarantine_path: None,
            };
            
            ledger.record_run(request, &result).await?;
            Ok(result)
        }
    }
}

fn calculate_msg_id(request: &SpellRequest) -> String {
    let json = serde_json::to_string(request).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}