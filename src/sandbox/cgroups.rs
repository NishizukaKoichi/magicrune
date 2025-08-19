#[cfg(target_os = "linux")]
pub fn try_enable_cgroups(cpu_ms: u64, mem_mb: u64, pids: u64) -> Result<Option<String>, String> {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    if std::env::var("MAGICRUNE_CGROUPS").ok().as_deref() != Some("1") {
        return Ok(None);
    }
    let parent = std::env::var("MAGICRUNE_CGROUP_PARENT").unwrap_or_else(|_| "/sys/fs/cgroup".to_string());
    let name = format!("magicrune_{}", std::process::id());
    let path = PathBuf::from(parent).join(&name);
    fs::create_dir_all(&path).map_err(|e| format!("create cgroup dir failed: {e}"))?;
    // memory.max
    if mem_mb > 0 {
        let mut f = fs::OpenOptions::new().write(true).open(path.join("memory.max")).map_err(|e| format!("open memory.max failed: {e}"))?;
        writeln!(f, "{}", (mem_mb as u64) * 1024 * 1024).map_err(|e| format!("write memory.max failed: {e}"))?;
    }
    // pids.max
    if pids > 0 {
        let mut f = fs::OpenOptions::new().write(true).open(path.join("pids.max")).map_err(|e| format!("open pids.max failed: {e}"))?;
        writeln!(f, "{}", pids).map_err(|e| format!("write pids.max failed: {e}"))?;
    }
    // cpu.max (best-effort mapping from ms)
    if cpu_ms > 0 {
        // Use period 100000 (100ms), quota proportional to cpu_ms within wall time is complex; use fixed 50000/100000 (50%) as conservative default
        let mut f = fs::OpenOptions::new().write(true).open(path.join("cpu.max")).map_err(|e| format!("open cpu.max failed: {e}"))?;
        writeln!(f, "50000 100000").map_err(|e| format!("write cpu.max failed: {e}"))?;
    }
    // join cgroup
    let mut f = fs::OpenOptions::new().write(true).open(path.join("cgroup.procs")).map_err(|e| format!("open cgroup.procs failed: {e}"))?;
    writeln!(f, "{}", std::process::id()).map_err(|e| format!("write cgroup.procs failed: {e}"))?;
    Ok(Some(path.display().to_string()))
}

#[cfg(not(target_os = "linux"))]
pub fn try_enable_cgroups(_cpu_ms: u64, _mem_mb: u64, _pids: u64) -> Result<Option<String>, String> { Ok(None) }
