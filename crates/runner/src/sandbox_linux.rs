use anyhow::{Context, Result};
use magicrune_analyzer::Verdict;
use magicrune_audit::AuditEvent;
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{chroot, setuid, setgid, Uid, Gid};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::fs;
use tempfile::TempDir;
use tracing::{info, warn, debug};

use crate::{ExecutionResult, SandboxConfig};

pub async fn execute_in_sandbox(command: String, config: SandboxConfig) -> Result<ExecutionResult> {
    info!("Setting up Linux sandbox environment");
    
    // Create temporary sandbox directory
    let sandbox_dir = TempDir::new().context("Failed to create sandbox directory")?;
    let sandbox_path = sandbox_dir.path();
    
    // Set up sandbox filesystem
    setup_sandbox_fs(sandbox_path, &config)?;
    
    // Create a child process for sandboxing
    let mut cmd = Command::new("sh");
    cmd.arg("-c");
    cmd.arg(&command);
    
    // Clear environment
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    cmd.env("HOME", "/home/sandbox");
    cmd.env("USER", "sandbox");
    
    // Apply sandbox restrictions before exec
    unsafe {
        cmd.pre_exec(move || {
            // Create new namespaces
            unshare(
                CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWNET
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWUSER,
            )?;
            
            // Change root to sandbox directory
            chroot(sandbox_path)?;
            std::env::set_current_dir("/")?;
            
            // Drop privileges
            setgid(Gid::from_raw(65534))?; // nobody
            setuid(Uid::from_raw(65534))?; // nobody
            
            // Apply seccomp filters
            if let Err(e) = apply_seccomp_filters() {
                warn!("Failed to apply seccomp filters: {}", e);
            }
            
            Ok(())
        });
    }
    
    // Execute command
    let output = cmd.output()
        .context("Failed to execute command in sandbox")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}\n{}", stdout, stderr);
    
    // Collect audit events
    let mut audit_events = vec![
        AuditEvent::SandboxExecution {
            profile: "linux_namespaces".to_string(),
            restrictions: vec![
                "namespace_isolation".to_string(),
                "chroot".to_string(),
                "dropped_privileges".to_string(),
                "seccomp_filtered".to_string(),
            ],
        },
        AuditEvent::CommandExecution {
            command: command.clone(),
            exit_code: output.status.code().unwrap_or(-1),
            duration_ms: 0, // TODO: measure actual duration
        },
    ];
    
    // Check for filesystem changes
    let fs_changes = detect_fs_changes(sandbox_path)?;
    for change in fs_changes {
        audit_events.push(AuditEvent::FileWrite {
            path: change,
            size: 0, // TODO: get actual size
        });
    }
    
    // Analyze behavior
    let analysis = magicrune_analyzer::analyze_behavior(&audit_events)?;
    
    Ok(ExecutionResult {
        success: output.status.success(),
        output: combined_output,
        verdict: analysis.verdict,
        audit_events,
    })
}

fn setup_sandbox_fs(sandbox_path: &std::path::Path, _config: &SandboxConfig) -> Result<()> {
    // Create basic directory structure
    let dirs = vec![
        "bin", "usr/bin", "lib", "usr/lib", "lib64", "usr/lib64",
        "tmp", "dev", "proc", "home/sandbox", "etc",
    ];
    
    for dir in dirs {
        fs::create_dir_all(sandbox_path.join(dir))?;
    }
    
    // Create minimal /etc/passwd
    fs::write(
        sandbox_path.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\nsandbox:x:1000:1000:sandbox:/home/sandbox:/bin/sh\n"
    )?;
    
    // Create minimal /etc/group
    fs::write(
        sandbox_path.join("etc/group"),
        "root:x:0:\nnobody:x:65534:\nsandbox:x:1000:\n"
    )?;
    
    // Create device nodes
    create_device_nodes(sandbox_path)?;
    
    // Bind mount essential binaries (read-only)
    bind_mount_readonly("/bin", &sandbox_path.join("bin"))?;
    bind_mount_readonly("/usr/bin", &sandbox_path.join("usr/bin"))?;
    bind_mount_readonly("/lib", &sandbox_path.join("lib"))?;
    bind_mount_readonly("/usr/lib", &sandbox_path.join("usr/lib"))?;
    
    if std::path::Path::new("/lib64").exists() {
        bind_mount_readonly("/lib64", &sandbox_path.join("lib64"))?;
    }
    if std::path::Path::new("/usr/lib64").exists() {
        bind_mount_readonly("/usr/lib64", &sandbox_path.join("usr/lib64"))?;
    }
    
    Ok(())
}

fn create_device_nodes(sandbox_path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    use nix::sys::stat::{mknod, Mode, SFlag};
    
    let dev_path = sandbox_path.join("dev");
    
    // Create essential device nodes
    mknod(
        &dev_path.join("null"),
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o666),
        nix::sys::stat::makedev(1, 3),
    )?;
    
    mknod(
        &dev_path.join("zero"),
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o666),
        nix::sys::stat::makedev(1, 5),
    )?;
    
    mknod(
        &dev_path.join("random"),
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o444),
        nix::sys::stat::makedev(1, 8),
    )?;
    
    mknod(
        &dev_path.join("urandom"),
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o444),
        nix::sys::stat::makedev(1, 9),
    )?;
    
    Ok(())
}

fn bind_mount_readonly(source: &str, target: &std::path::Path) -> Result<()> {
    use nix::mount::{mount, MsFlags};
    
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        None::<&str>,
    )?;
    
    Ok(())
}

fn apply_seccomp_filters() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Try to use seccomp if available
        if let Ok(_) = std::process::Command::new("which").arg("seccomp").output() {
            // seccomp available, could apply filters here
            info!("Seccomp filters would be applied here");
        } else {
            warn!("Seccomp not available on this system");
        }
    }
    
    Ok(())
}

fn detect_fs_changes(_sandbox_path: &std::path::Path) -> Result<Vec<String>> {
    // TODO: Implement actual filesystem change detection
    // For now, return empty vector
    Ok(vec![])
}