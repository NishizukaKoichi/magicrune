use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "magicrune")]
#[command(author, version, about = "MagicRune Policy Runner - Safe execution of AI-generated and external code", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, help = "Path to policy configuration file")]
    policy: Option<PathBuf>,

    #[arg(long, global = true, help = "Enable debug logging")]
    debug: bool,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Run a command with automatic policy enforcement")]
    Run {
        #[arg(help = "Command to execute")]
        command: String,

        #[arg(long, help = "Path to signature file for verification")]
        signature: Option<PathBuf>,

        #[arg(long, help = "Force sandbox execution even for trusted code")]
        force_sandbox: bool,
    },

    #[command(about = "Dry-run a command in sandbox (read-only, no network)")]
    Dryrun {
        #[arg(help = "Command to execute")]
        command: String,
    },

    #[command(about = "Analyze audit logs and generate verdict")]
    Analyze {
        #[arg(help = "Path to audit log JSON file")]
        audit_log: PathBuf,

        #[arg(long, help = "Output format", default_value = "human")]
        format: OutputFormat,
    },

    #[command(about = "Promote and sign analyzed artifacts")]
    Promote {
        #[arg(help = "Path to artifact to promote")]
        artifact: PathBuf,

        #[arg(long, help = "Sign the artifact after promotion")]
        sign: bool,

        #[arg(long, help = "Path to signing key")]
        key: Option<PathBuf>,
    },

    #[command(subcommand, about = "Manage trusted keys")]
    Keys(KeyCommands),

    #[command(subcommand, about = "Manage cache")]
    Cache(CacheCommands),

    #[command(about = "CI/CD scanning mode")]
    CiScan {
        #[arg(long, help = "Paths to scan (comma-separated)")]
        paths: String,

        #[arg(long, help = "Enforce external source policy")]
        enforce_external: bool,
    },

    #[command(about = "Generate CI verdict report")]
    CiReport {
        #[arg(long, help = "Pull request number")]
        pr: Option<u32>,

        #[arg(long, help = "Output file path")]
        output: Option<PathBuf>,
    },

    #[command(about = "Initialize MagicRune configuration")]
    Init {
        #[arg(long, help = "Force overwrite existing configuration")]
        force: bool,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    #[command(about = "Add a trusted public key")]
    Add {
        #[arg(help = "Path to public key file")]
        pubkey: PathBuf,
    },

    #[command(about = "List trusted keys")]
    List,

    #[command(about = "Remove a trusted key")]
    Remove {
        #[arg(help = "Key ID or fingerprint")]
        key_id: String,
    },
}

#[derive(Subcommand)]
enum CacheCommands {
    #[command(about = "Pin a package version to cache")]
    Allow {
        #[command(subcommand)]
        action: AllowAction,
    },

    #[command(about = "Clear cache")]
    Clear {
        #[arg(long, help = "Clear all cache entries")]
        all: bool,

        #[arg(long, help = "Clear entries older than N days")]
        older_than: Option<u32>,
    },

    #[command(about = "Show cache statistics")]
    Stats,
}

#[derive(Subcommand)]
enum AllowAction {
    #[command(about = "Pin a specific package version")]
    Pin {
        #[arg(help = "Package name and version (e.g., react@18.2.0)")]
        package: String,

        #[arg(long, help = "SHA256 hash of the package")]
        sha256: String,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum OutputFormat {
    Human,
    Json,
    Markdown,
}

fn init_logging(debug: bool) -> Result<()> {
    let filter = if debug { "debug" } else { "info" };
    
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    Ok(())
}

fn print_banner() {
    println!("{}", "╔═══════════════════════════════════════╗".cyan());
    println!("{}", "║       MagicRune Policy Runner         ║".cyan());
    println!("{}", "║   Secure Code Execution Framework     ║".cyan());
    println!("{}", "╚═══════════════════════════════════════╝".cyan());
    println!();
}

async fn handle_run(
    command: String,
    signature: Option<PathBuf>,
    force_sandbox: bool,
    policy: magicrune_policy::PolicyConfig,
) -> Result<()> {
    use magicrune_detector::detect_external_sources;
    use magicrune_runner::{RunContext, RunMode};
    use magicrune_policy::TrustLevel;

    info!("Executing command: {}", command);

    // 署名検証
    let trust_level = if let Some(sig_path) = signature {
        match magicrune_sign::verify_command_signature(&command, &sig_path, &policy.signing) {
            Ok(true) => {
                info!("{}", "✓ Signature verified".green());
                TrustLevel::L0
            }
            Ok(false) => {
                error!("{}", "✗ Signature verification failed".red());
                return Err(anyhow::anyhow!("Signature verification failed"));
            }
            Err(e) => {
                error!("Signature verification error: {}", e);
                return Err(e);
            }
        }
    } else if detect_external_sources(&command)? {
        warn!("{}", "⚠ External source detected - enforcing sandbox".yellow());
        TrustLevel::L2
    } else {
        info!("{}", "◆ AI-generated code (no external sources)".blue());
        TrustLevel::L1
    };

    // 実行モード決定
    let run_mode = match trust_level {
        TrustLevel::L0 if !force_sandbox => RunMode::Direct,
        TrustLevel::L1 if policy.default.ai_pure_generated == magicrune_policy::AiGeneratedPolicy::AllowLocal => {
            RunMode::Local
        }
        _ => RunMode::Sandbox,
    };

    let context = RunContext {
        command: command.clone(),
        trust_level,
        run_mode,
        policy: policy.clone(),
    };

    // 実行
    let result = magicrune_runner::execute(context).await?;

    // 結果表示
    match result.verdict {
        magicrune_analyzer::Verdict::Green => {
            println!("{}", "✓ Execution completed successfully (Green)".green());
        }
        magicrune_analyzer::Verdict::Yellow => {
            println!("{}", "⚠ Execution completed with warnings (Yellow)".yellow());
            println!("Review required before production use.");
        }
        magicrune_analyzer::Verdict::Red => {
            println!("{}", "✗ Execution blocked - security risk detected (Red)".red());
            return Err(anyhow::anyhow!("Execution blocked due to security risk"));
        }
    }

    if !result.output.is_empty() {
        println!("\nOutput:");
        println!("{}", result.output);
    }

    Ok(())
}

async fn handle_dryrun(command: String, policy: magicrune_policy::PolicyConfig) -> Result<()> {
    info!("Dry-run mode: {}", command);
    
    let context = magicrune_runner::RunContext {
        command: command.clone(),
        trust_level: magicrune_policy::TrustLevel::L2, // Always sandbox in dryrun
        run_mode: magicrune_runner::RunMode::Dryrun,
        policy,
    };

    let result = magicrune_runner::execute(context).await?;
    
    println!("{}", "Dry-run completed (read-only, no network)".cyan());
    println!("\nAnalysis Result:");
    println!("  Verdict: {:?}", result.verdict);
    println!("\nDetected behaviors:");
    for event in &result.audit_events {
        println!("  - {}", event);
    }

    Ok(())
}

async fn handle_analyze(audit_log: PathBuf, format: OutputFormat) -> Result<()> {
    let log_content = std::fs::read_to_string(&audit_log)
        .with_context(|| format!("Failed to read audit log: {}", audit_log.display()))?;

    let events: Vec<magicrune_audit::AuditEvent> = log_content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line))
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse audit log")?;

    let analysis = magicrune_analyzer::analyze_behavior(&events)?;

    match format {
        OutputFormat::Human => {
            println!("Behavior Analysis Report");
            println!("========================");
            println!("Verdict: {:?}", analysis.verdict);
            println!("\nRisk Score: {}", analysis.risk_score);
            println!("\nDetected Behaviors:");
            for behavior in &analysis.behaviors {
                println!("  - {}: {}", behavior.category, behavior.description);
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&analysis)?);
        }
        OutputFormat::Markdown => {
            println!("# Behavior Analysis Report\n");
            println!("**Verdict**: {:?}\n", analysis.verdict);
            println!("**Risk Score**: {}\n", analysis.risk_score);
            println!("## Detected Behaviors\n");
            for behavior in &analysis.behaviors {
                println!("- **{}**: {}", behavior.category, behavior.description);
            }
        }
    }

    Ok(())
}

async fn handle_init(force: bool) -> Result<()> {
    use magicrune_policy::PolicyConfig;

    println!("{}", "Initializing MagicRune configuration...".cyan());

    let policy_path = PolicyConfig::get_policy_path()?;
    
    if policy_path.exists() && !force {
        println!("{}", "⚠ Configuration already exists".yellow());
        println!("Use --force to overwrite");
        return Ok(());
    }

    // Create directories
    let magicrune_dir = policy_path.parent().unwrap();
    std::fs::create_dir_all(magicrune_dir)?;
    std::fs::create_dir_all(magicrune_dir.join("trusted_keys"))?;
    std::fs::create_dir_all(magicrune_dir.join("audit"))?;
    std::fs::create_dir_all(magicrune_dir.join("cache"))?;

    // Write default policy
    PolicyConfig::ensure_default_config()?;

    println!("{}", "✓ MagicRune initialized successfully".green());
    println!("\nCreated:");
    println!("  - {}", policy_path.display());
    println!("  - {}/trusted_keys/", magicrune_dir.display());
    println!("  - {}/audit/", magicrune_dir.display());
    println!("  - {}/cache/", magicrune_dir.display());

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    init_logging(cli.debug)?;

    // Load policy
    let policy = if let Some(policy_path) = cli.policy {
        magicrune_policy::PolicyConfig::load_from_file(policy_path)?
    } else {
        magicrune_policy::PolicyConfig::ensure_default_config()?;
        magicrune_policy::PolicyConfig::load_from_file(
            magicrune_policy::PolicyConfig::get_policy_path()?
        )?
    };

    if !matches!(cli.command, Commands::Init { .. }) {
        print_banner();
    }

    match cli.command {
        Commands::Run { command, signature, force_sandbox } => {
            handle_run(command, signature, force_sandbox, policy).await?;
        }
        Commands::Dryrun { command } => {
            handle_dryrun(command, policy).await?;
        }
        Commands::Analyze { audit_log, format } => {
            handle_analyze(audit_log, format).await?;
        }
        Commands::Promote { artifact, sign, key } => {
            todo!("Implement promote command");
        }
        Commands::Keys(key_cmd) => {
            todo!("Implement key management");
        }
        Commands::Cache(cache_cmd) => {
            todo!("Implement cache management");
        }
        Commands::CiScan { paths, enforce_external } => {
            todo!("Implement CI scanning");
        }
        Commands::CiReport { pr, output } => {
            todo!("Implement CI reporting");
        }
        Commands::Init { force } => {
            handle_init(force).await?;
        }
    }

    Ok(())
}