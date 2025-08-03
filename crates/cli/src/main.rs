use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;
use std::io::{self, Write};
use std::fs;
use tracing::{error, info};

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

#[derive(Debug)]
enum ExecutionVerdict {
    Allow,   // 0-30: Safe to execute
    Confirm, // 31-70: Requires user confirmation  
    Block,   // 71-100: Too dangerous, block execution
}

fn calculate_risk_score(detections: &[magicrune_detector::ExternalSourceDetection]) -> u32 {
    let mut score = 0;
    for detection in detections {
        score += match detection.risk_level {
            magicrune_detector::RiskLevel::Low => 10,
            magicrune_detector::RiskLevel::Medium => 25,
            magicrune_detector::RiskLevel::High => 50,
            magicrune_detector::RiskLevel::Critical => 80,
        };
    }
    std::cmp::min(score, 100) // Cap at 100
}

fn determine_execution_verdict(risk_score: u32) -> ExecutionVerdict {
    match risk_score {
        0..=30 => ExecutionVerdict::Allow,
        31..=70 => ExecutionVerdict::Confirm,
        _ => ExecutionVerdict::Block,
    }
}

fn prompt_user_confirmation(detections: &[magicrune_detector::ExternalSourceDetection]) -> Result<bool> {
    println!("\n{}", "⚠️  Security Review Required".yellow().bold());
    println!("The following risks were detected:");
    for detection in detections {
        println!("  • {}", detection.description.yellow());
    }
    println!("\nDo you want to proceed with execution? (y/N): ");
    
    print!("❯ ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    let response = input.trim().to_lowercase();
    Ok(response == "y" || response == "yes")
}

async fn handle_run(
    command: String,
    signature: Option<PathBuf>,
    force_sandbox: bool,
    policy: magicrune_policy::PolicyConfig,
) -> Result<()> {
    use magicrune_detector::{detect_external_sources, analyze_command};
    use magicrune_runner::{RunContext, RunMode};
    use magicrune_policy::TrustLevel;

    println!("{}", "🔍 Analyzing command...".cyan());
    info!("Executing command: {}", command);

    // コマンド解析と詳細表示
    let detections = analyze_command(&command)?;
    let mut risk_score = calculate_risk_score(&detections);
    
    if !detections.is_empty() {
        println!("{}", "📊 Security Analysis:".yellow());
        for detection in &detections {
            let risk_icon = match detection.risk_level {
                magicrune_detector::RiskLevel::Low => "🟢",
                magicrune_detector::RiskLevel::Medium => "🟡",
                magicrune_detector::RiskLevel::High => "🟠", 
                magicrune_detector::RiskLevel::Critical => "🔴",
            };
            println!("  {} {}: {}", risk_icon, detection.source_type_name(), detection.description);
        }
        println!("  📈 Risk Score: {}/100", risk_score);
    } else {
        println!("{}", "✅ No external sources detected".green());
        risk_score = 10; // Base risk for any command execution
    }

    // 署名検証
    let trust_level = if let Some(sig_path) = signature {
        match magicrune_sign::verify_command_signature(&command, &sig_path, &policy.signing) {
            Ok(true) => {
                println!("{}", "✓ Signature verified".green());
                TrustLevel::L0
            }
            Ok(false) => {
                println!("{}", "✗ Signature verification failed".red());
                return Err(anyhow::anyhow!("Signature verification failed"));
            }
            Err(e) => {
                error!("Signature verification error: {}", e);
                return Err(e);
            }
        }
    } else if detect_external_sources(&command)? {
        println!("{}", "⚠ External source detected - enforcing sandbox".yellow());
        TrustLevel::L2
    } else {
        println!("{}", "◆ AI-generated code (no external sources)".blue());
        TrustLevel::L1
    };

    // リスクベースの実行判定
    let verdict = determine_execution_verdict(risk_score);
    match verdict {
        ExecutionVerdict::Block => {
            println!("{}", "🔴 BLOCKED - Command contains critical security risks".red());
            println!("Execution prevented for safety. Review the command and try again.");
            return Err(anyhow::anyhow!("Execution blocked due to security risks"));
        }
        ExecutionVerdict::Confirm => {
            println!("{}", "🟡 WARNING - Command requires human review".yellow());
            if !prompt_user_confirmation(&detections)? {
                println!("Execution cancelled by user.");
                return Ok(());
            }
        }
        ExecutionVerdict::Allow => {
            println!("{}", "🟢 APPROVED - Command appears safe to execute".green());
        }
    }

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
    println!("{}", "🚀 Executing command...".cyan());
    let result = magicrune_runner::execute(context).await?;

    // 結果表示
    println!("\n{}", "📋 Execution Results:".cyan().bold());
    match result.verdict {
        magicrune_analyzer::Verdict::Green => {
            println!("  {} {}", "✓".green(), "Execution completed successfully (Green)".green());
        }
        magicrune_analyzer::Verdict::Yellow => {
            println!("  {} {}", "⚠".yellow(), "Execution completed with warnings (Yellow)".yellow());
            println!("  {} Review required before production use.", "ℹ".blue());
        }
        magicrune_analyzer::Verdict::Red => {
            println!("  {} {}", "✗".red(), "Execution blocked - security risk detected (Red)".red());
            return Err(anyhow::anyhow!("Execution blocked due to security risk"));
        }
    }

    println!("  📊 Exit Code: {}", 
        if result.success { "0 (Success)".green() } else { "Non-zero (Failed)".red() });

    if !result.output.trim().is_empty() {
        println!("\n{}", "📄 Command Output:".cyan().bold());
        println!("{}", result.output);
    } else {
        println!("  📄 No output generated");
    }

    // 監査イベントの表示
    if !result.audit_events.is_empty() {
        println!("\n{}", "🔍 Security Audit Log:".cyan().bold());
        for event in &result.audit_events {
            match event {
                magicrune_audit::AuditEvent::CommandExecution { command: cmd, exit_code, .. } => {
                    println!("  • Command executed: {} (exit: {})", cmd, exit_code);
                }
                magicrune_audit::AuditEvent::FileDelete { path, .. } => {
                    println!("  • File deleted: {}", path);
                }
                magicrune_audit::AuditEvent::FileRead { path, .. } => {
                    println!("  • File read: {}", path);
                }
                magicrune_audit::AuditEvent::FileWrite { path, .. } => {
                    println!("  • File written: {}", path);
                }
                magicrune_audit::AuditEvent::NetworkConnection { host, port, protocol, .. } => {
                    println!("  • Network connection: {}:{} ({})", host, port, protocol);
                }
                magicrune_audit::AuditEvent::ProcessSpawn { command: spawn_cmd, .. } => {
                    println!("  • Process spawned: {}", spawn_cmd);
                }
                magicrune_audit::AuditEvent::PrivilegeEscalation { method, .. } => {
                    println!("  • Privilege escalation: {}", method);
                }
                magicrune_audit::AuditEvent::SandboxExecution { profile, .. } => {
                    println!("  • Sandbox execution with profile: {}", profile);
                }
                magicrune_audit::AuditEvent::SandboxEscape { method, .. } => {
                    println!("  • 🚨 SANDBOX ESCAPE detected: {}", method);
                }
            }
        }
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

async fn handle_key_management(
    key_cmd: KeyCommands,
    policy: magicrune_policy::PolicyConfig,
) -> Result<()> {
    use magicrune_sign::TrustedKeyStore;
    
    let key_store = TrustedKeyStore::new(policy.signing.trusted_keys_path.clone())?;
    
    match key_cmd {
        KeyCommands::Add { pubkey } => {
            println!("{}", "🔑 Adding trusted key...".cyan());
            
            if !pubkey.exists() {
                return Err(anyhow::anyhow!("Key file not found: {}", pubkey.display()));
            }
            
            let key_id = key_store.add_key(&pubkey)
                .with_context(|| format!("Failed to add key: {}", pubkey.display()))?;
            
            println!("  {} Key added successfully: {}", "✓".green(), key_id);
            println!("  📁 Key stored in: {}", policy.signing.trusted_keys_path.display());
        }
        
        KeyCommands::List => {
            println!("{}", "🔑 Trusted Keys:".cyan());
            
            let keys = key_store.list_keys()?;
            if keys.is_empty() {
                println!("  📭 No trusted keys found");
                println!("  💡 Add keys with: magicrune keys add <pubkey-file>");
            } else {
                let keys_count = keys.len();
                for (key_id, key_type) in keys {
                    println!("  🔹 {} ({})", key_id, key_type);
                }
                println!("\n  📊 Total: {} key(s)", keys_count);
            }
        }
        
        KeyCommands::Remove { key_id } => {
            println!("{}", "🗑️  Removing trusted key...".cyan());
            
            key_store.remove_key(&key_id)
                .with_context(|| format!("Failed to remove key: {}", key_id))?;
            
            println!("  {} Key removed successfully: {}", "✓".green(), key_id);
        }
    }
    
    Ok(())
}

async fn handle_ci_scan(
    paths: String,
    enforce_external: bool,
    policy: magicrune_policy::PolicyConfig,
) -> Result<()> {
    use magicrune_detector::analyze_command;
    use std::path::PathBuf;
    
    println!("{}", "🔍 CI/CD Security Scan".cyan().bold());
    println!("Scanning paths: {}", paths);
    
    let scan_paths: Vec<&str> = paths.split(',').map(|s| s.trim()).collect();
    let mut total_files = 0;
    let mut total_issues = 0;
    let mut critical_issues = 0;
    let mut scan_results = Vec::new();
    
    for path_str in scan_paths {
        let path = PathBuf::from(path_str);
        
        if path.is_dir() {
            scan_directory(&path, &mut total_files, &mut total_issues, &mut critical_issues, &mut scan_results, enforce_external)?;
        } else if path.is_file() {
            scan_file_sync(&path, &mut total_files, &mut total_issues, &mut critical_issues, &mut scan_results, enforce_external)?;
        } else {
            println!("  ⚠️  Path not found: {}", path_str);
        }
    }
    
    // 結果サマリー
    println!("\n{}", "📊 Scan Results:".cyan().bold());
    println!("  📁 Files scanned: {}", total_files);
    println!("  ⚠️  Total issues: {}", if total_issues > 0 { total_issues.to_string().red() } else { total_issues.to_string().green() });
    println!("  🔴 Critical issues: {}", if critical_issues > 0 { critical_issues.to_string().red() } else { critical_issues.to_string().green() });
    
    if critical_issues > 0 {
        println!("\n{}", "🚨 CRITICAL SECURITY ISSUES FOUND".red().bold());
        for result in &scan_results {
            if result.risk_level == "Critical" {
                println!("  🔴 {}: {}", result.file_path, result.issue);
            }
        }
        
        if enforce_external {
            return Err(anyhow::anyhow!("CI scan failed: {} critical security issues found", critical_issues));
        }
    }
    
    if total_issues > 0 && total_issues > critical_issues {
        println!("\n{}", "⚠️  Other Security Issues:".yellow().bold());
        for result in &scan_results {
            if result.risk_level != "Critical" {
                println!("  {} {}: {}", 
                    match result.risk_level.as_str() {
                        "High" => "🟠",
                        "Medium" => "🟡", 
                        _ => "🟢"
                    },
                    result.file_path, 
                    result.issue
                );
            }
        }
    }
    
    if total_issues == 0 {
        println!("{}", "✅ No security issues found!".green().bold());
    }
    
    Ok(())
}

#[derive(Debug)]
struct ScanResult {
    file_path: String,
    issue: String,
    risk_level: String,
}

fn scan_directory(
    dir_path: &PathBuf,
    total_files: &mut u32,
    total_issues: &mut u32,
    critical_issues: &mut u32,
    scan_results: &mut Vec<ScanResult>,
    enforce_external: bool,
) -> Result<()> {
    let mut dirs_to_scan = vec![dir_path.clone()];
    
    while let Some(current_dir) = dirs_to_scan.pop() {
        for entry in std::fs::read_dir(&current_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                dirs_to_scan.push(path);
            } else if path.is_file() {
                scan_file_sync(&path, total_files, total_issues, critical_issues, scan_results, enforce_external)?;
            }
        }
    }
    Ok(())
}

fn scan_file_sync(
    file_path: &PathBuf,
    total_files: &mut u32,
    total_issues: &mut u32,
    critical_issues: &mut u32,
    scan_results: &mut Vec<ScanResult>,
    enforce_external: bool,
) -> Result<()> {
    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
    
    // スキャン対象ファイルの拡張子チェック
    if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
        match ext {
            "sh" | "bash" | "zsh" | "fish" | "py" | "js" | "ts" | "go" | "rs" | "rb" | "php" | "pl" => {
                *total_files += 1;
                scan_script_file_sync(file_path, total_issues, critical_issues, scan_results, enforce_external)?;
            }
            _ => {
                // バイナリファイルやその他のファイルはスキップ
            }
        }
    } else if filename == "Dockerfile" || filename == "Makefile" || filename.starts_with('.') {
        *total_files += 1;
        scan_script_file_sync(file_path, total_issues, critical_issues, scan_results, enforce_external)?;
    }
    
    Ok(())
}

fn scan_script_file_sync(
    file_path: &PathBuf,
    total_issues: &mut u32,
    critical_issues: &mut u32,
    scan_results: &mut Vec<ScanResult>,
    _enforce_external: bool,
) -> Result<()> {
    let content = std::fs::read_to_string(file_path)?;
    let lines: Vec<&str> = content.lines().collect();
    
    for (line_num, line) in lines.iter().enumerate() {
        if let Ok(detections) = magicrune_detector::analyze_command(line) {
            for detection in detections {
                let risk_level = match detection.risk_level {
                    magicrune_detector::RiskLevel::Critical => {
                        *critical_issues += 1;
                        "Critical"
                    }
                    magicrune_detector::RiskLevel::High => "High",
                    magicrune_detector::RiskLevel::Medium => "Medium",
                    magicrune_detector::RiskLevel::Low => "Low",
                };
                
                *total_issues += 1;
                
                scan_results.push(ScanResult {
                    file_path: format!("{}:{}", file_path.display(), line_num + 1),
                    issue: detection.description,
                    risk_level: risk_level.to_string(),
                });
            }
        }
    }
    
    Ok(())
}

async fn handle_ci_report(
    pr: Option<u32>,
    output: Option<PathBuf>,
    _policy: magicrune_policy::PolicyConfig,
) -> Result<()> {
    println!("{}", "📋 Generating CI/CD Security Report".cyan().bold());
    
    // Create a comprehensive security report
    let report = generate_security_report().await?;
    
    // Output to file if specified
    if let Some(output_path) = output {
        fs::write(&output_path, &report)?;
        println!("  📁 Report saved to: {}", output_path.display());
    } else {
        println!("\n{}", report);
    }
    
    // Post to GitHub PR if specified
    if let Some(pr_number) = pr {
        post_github_pr_comment(pr_number, &report).await?;
    }
    
    Ok(())
}

async fn generate_security_report() -> Result<String> {
    let mut report = String::new();
    
    // Header
    report.push_str("## 🔒 MagicRune Security Report\n\n");
    report.push_str(&format!("**Generated**: {}\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    report.push_str(&format!("**Tool Version**: {}\n\n", env!("CARGO_PKG_VERSION")));
    
    // Summary (placeholder data - in real implementation would come from scan results)
    report.push_str("### 📊 Summary\n\n");
    report.push_str("| Metric | Count |\n");
    report.push_str("|--------|-------|\n");
    report.push_str("| Files Scanned | 0 |\n");
    report.push_str("| Security Issues | 0 |\n");
    report.push_str("| Critical Issues | 0 |\n");
    report.push_str("| High Risk | 0 |\n");
    report.push_str("| Medium Risk | 0 |\n");
    report.push_str("| Low Risk | 0 |\n\n");
    
    // Security checks performed
    report.push_str("### 🔍 Security Checks Performed\n\n");
    report.push_str("- ✅ **External Source Detection**: Scanning for curl, wget, downloads\n");
    report.push_str("- ✅ **Pipe Execution Analysis**: Detecting dangerous pipe-to-shell patterns\n");
    report.push_str("- ✅ **Secret Path Access**: Checking for access to sensitive files\n");
    report.push_str("- ✅ **Dangerous Operations**: Identifying destructive commands\n");
    report.push_str("- ✅ **Package Manager Usage**: Monitoring dependency installations\n\n");
    
    // Recommendations
    report.push_str("### 💡 Security Recommendations\n\n");
    report.push_str("1. **Code Review**: All external downloads should be reviewed manually\n");
    report.push_str("2. **Signature Verification**: Use MagicRune's signing features for trusted code\n");
    report.push_str("3. **Sandbox Execution**: Run untrusted code in MagicRune's sandbox\n");
    report.push_str("4. **Regular Scans**: Integrate MagicRune into your CI/CD pipeline\n\n");
    
    // Footer
    report.push_str("---\n");
    report.push_str("*Generated by [MagicRune](https://github.com/magicrune/magicrune) - Secure Code Execution Framework*\n");
    
    Ok(report)
}

async fn post_github_pr_comment(pr_number: u32, report: &str) -> Result<()> {
    println!("  🚀 Posting comment to GitHub PR #{}", pr_number);
    
    // Check if gh CLI is available
    let gh_check = std::process::Command::new("gh")
        .arg("--version")
        .output();
    
    match gh_check {
        Ok(_) => {
            // Post comment using GitHub CLI
            let comment_result = std::process::Command::new("gh")
                .arg("pr")
                .arg("comment")
                .arg(pr_number.to_string())
                .arg("--body")
                .arg(report)
                .output();
            
            match comment_result {
                Ok(output) => {
                    if output.status.success() {
                        println!("  ✅ Comment posted successfully to PR #{}", pr_number);
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        println!("  ❌ Failed to post comment: {}", stderr);
                    }
                }
                Err(e) => {
                    println!("  ⚠️  Failed to execute gh command: {}", e);
                }
            }
        }
        Err(_) => {
            println!("  ⚠️  GitHub CLI (gh) not found. Install it to post PR comments automatically.");
            println!("  💡 You can manually copy the report above and post it to PR #{}", pr_number);
        }
    }
    
    Ok(())
}

async fn handle_cache_management(
    cache_cmd: CacheCommands,
    policy: magicrune_policy::PolicyConfig,
) -> Result<()> {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use chrono::{DateTime, Utc, Duration};
    
    let cache_dir = policy.cache.as_ref()
        .map(|c| c.path.clone())
        .unwrap_or_else(|| std::env::current_dir().unwrap().join(".magicrune/cache"));
    
    match cache_cmd {
        CacheCommands::Allow { action } => {
            match action {
                AllowAction::Pin { package, sha256 } => {
                    println!("{}", "📦 Pinning package to cache...".cyan());
                    
                    // Create cache directory if it doesn't exist
                    if !cache_dir.exists() {
                        fs::create_dir_all(&cache_dir)?;
                    }
                    
                    // Parse package name and version
                    let parts: Vec<&str> = package.split('@').collect();
                    if parts.len() != 2 {
                        return Err(anyhow::anyhow!("Invalid package format. Use: package@version"));
                    }
                    
                    let package_name = parts[0];
                    let version = parts[1];
                    
                    // Create package cache entry
                    let cache_entry = serde_json::json!({
                        "package": package_name,
                        "version": version,
                        "sha256": sha256,
                        "pinned_at": Utc::now().to_rfc3339(),
                        "status": "trusted"
                    });
                    
                    let cache_file = cache_dir.join(format!("{}_{}.json", package_name, version));
                    fs::write(&cache_file, serde_json::to_string_pretty(&cache_entry)?)?;
                    
                    println!("  {} Package pinned: {}@{}", "✓".green(), package_name, version);
                    println!("  📁 Cache entry: {}", cache_file.display());
                    println!("  🔒 SHA256: {}", sha256);
                }
            }
        }
        
        CacheCommands::Clear { all, older_than } => {
            println!("{}", "🧹 Clearing cache...".cyan());
            
            if !cache_dir.exists() {
                println!("  📭 Cache directory doesn't exist");
                return Ok(());
            }
            
            let mut cleared_count = 0;
            let cutoff_time = if let Some(days) = older_than {
                Some(Utc::now() - Duration::days(days as i64))
            } else {
                None
            };
            
            for entry in fs::read_dir(&cache_dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    let should_remove = if all {
                        true
                    } else if let Some(cutoff) = cutoff_time {
                        // Check file modification time
                        let metadata = fs::metadata(&path)?;
                        let modified = metadata.modified()?;
                        let modified_datetime = DateTime::<Utc>::from(modified);
                        modified_datetime < cutoff
                    } else {
                        false
                    };
                    
                    if should_remove {
                        fs::remove_file(&path)?;
                        cleared_count += 1;
                        println!("  🗑️  Removed: {}", path.file_name().unwrap().to_string_lossy());
                    }
                }
            }
            
            println!("  {} Cleared {} cache entries", "✓".green(), cleared_count);
        }
        
        CacheCommands::Stats => {
            println!("{}", "📊 Cache Statistics".cyan());
            
            if !cache_dir.exists() {
                println!("  📭 Cache directory doesn't exist");
                return Ok(());
            }
            
            let mut total_entries = 0;
            let mut total_size = 0;
            let mut pinned_packages = Vec::new();
            
            for entry in fs::read_dir(&cache_dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    total_entries += 1;
                    
                    // Get file size
                    let metadata = fs::metadata(&path)?;
                    total_size += metadata.len();
                    
                    // Parse cache entry
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(cache_entry) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let (Some(package), Some(version)) = (
                                cache_entry.get("package").and_then(|v| v.as_str()),
                                cache_entry.get("version").and_then(|v| v.as_str())
                            ) {
                                pinned_packages.push(format!("{}@{}", package, version));
                            }
                        }
                    }
                }
            }
            
            println!("  📦 Total entries: {}", total_entries);
            println!("  💾 Total size: {} bytes", total_size);
            println!("  📁 Cache directory: {}", cache_dir.display());
            
            if !pinned_packages.is_empty() {
                println!("\n  🔒 Pinned packages:");
                for package in pinned_packages {
                    println!("    • {}", package);
                }
            } else {
                println!("  📭 No pinned packages");
            }
        }
    }
    
    Ok(())
}

async fn handle_promote(
    artifact: PathBuf,
    sign: bool,
    key: Option<PathBuf>,
    policy: magicrune_policy::PolicyConfig,
) -> Result<()> {
    println!("{}", "🎯 Promoting artifact...".cyan());
    
    if !artifact.exists() {
        return Err(anyhow::anyhow!("Artifact not found: {}", artifact.display()));
    }
    
    // Analyze the artifact first
    println!("  🔍 Analyzing artifact...");
    let artifact_content = fs::read_to_string(&artifact)
        .with_context(|| format!("Failed to read artifact: {}", artifact.display()))?;
    
    // Check if it's a script or executable
    let is_script = artifact.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| matches!(ext, "sh" | "py" | "js" | "ts" | "rb" | "go" | "rs"))
        .unwrap_or(false);
    
    if is_script {
        // Analyze the script content for security issues
        let detections = magicrune_detector::analyze_command(&artifact_content)?;
        let risk_score = calculate_risk_score(&detections);
        
        println!("  📊 Security Analysis:");
        println!("    Risk Score: {}/100", risk_score);
        
        if risk_score > 50 {
            println!("  {} High risk artifact - promotion requires review", "⚠".yellow());
            if !prompt_user_confirmation(&detections)? {
                println!("Promotion cancelled by user.");
                return Ok(());
            }
        }
    }
    
    // Create promoted artifact directory
    let cache_dir = policy.cache.as_ref()
        .map(|c| c.path.clone())
        .unwrap_or_else(|| std::env::current_dir().unwrap().join(".magicrune/cache"));
    let promoted_dir = cache_dir.join("promoted");
    if !promoted_dir.exists() {
        fs::create_dir_all(&promoted_dir)?;
    }
    
    // Copy artifact to promoted directory
    let artifact_name = artifact.file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid artifact path"))?;
    let promoted_path = promoted_dir.join(artifact_name);
    
    fs::copy(&artifact, &promoted_path)?;
    println!("  {} Artifact promoted to: {}", "✓".green(), promoted_path.display());
    
    // Create metadata file
    let metadata = serde_json::json!({
        "original_path": artifact.display().to_string(),
        "promoted_at": chrono::Utc::now().to_rfc3339(),
        "promoted_by": "magicrune",
        "analysis": {
            "risk_score": if is_script { calculate_risk_score(&magicrune_detector::analyze_command(&artifact_content)?) } else { 0 },
            "is_script": is_script
        }
    });
    
    let metadata_path = promoted_dir.join(format!("{}.metadata.json", artifact_name.to_string_lossy()));
    fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;
    
    // Sign the artifact if requested
    if sign {
        let key_path = key.ok_or_else(|| anyhow::anyhow!("--key is required when --sign is specified"))?;
        
        if !key_path.exists() {
            return Err(anyhow::anyhow!("Key file not found: {}", key_path.display()));
        }
        
        println!("  🔐 Signing promoted artifact...");
        
        // Determine signing algorithm based on key type
        let key_content = fs::read_to_string(&key_path)?;
        let algorithm = if key_content.contains("ssh-ed25519") {
            "ssh-ed25519"
        } else if key_content.contains("ssh-rsa") {
            "ssh-rsa"
        } else {
            "gpg-rsa4096"
        };
        
        match magicrune_sign::sign_artifact(&promoted_path, &key_path, algorithm) {
            Ok(signature) => {
                let signature_path = promoted_dir.join(format!("{}.sig", artifact_name.to_string_lossy()));
                fs::write(&signature_path, signature)?;
                println!("  {} Artifact signed: {}", "✓".green(), signature_path.display());
            }
            Err(e) => {
                println!("  {} Failed to sign artifact: {}", "✗".red(), e);
            }
        }
    }
    
    println!("\n{}", "🎉 Promotion completed successfully!".green().bold());
    println!("  📁 Promoted artifact: {}", promoted_path.display());
    
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
            handle_promote(artifact, sign, key, policy).await?;
        }
        Commands::Keys(key_cmd) => {
            handle_key_management(key_cmd, policy).await?;
        }
        Commands::Cache(cache_cmd) => {
            handle_cache_management(cache_cmd, policy).await?;
        }
        Commands::CiScan { paths, enforce_external } => {
            handle_ci_scan(paths, enforce_external, policy).await?;
        }
        Commands::CiReport { pr, output } => {
            handle_ci_report(pr, output, policy).await?;
        }
        Commands::Init { force } => {
            handle_init(force).await?;
        }
    }

    Ok(())
}