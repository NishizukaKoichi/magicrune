#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxKind {
    Wasi,
    Linux,
}

pub struct SandboxSpec {
    pub wall_sec: u64,
    pub cpu_ms: u64,
    pub memory_mb: u64,
    pub pids: u64,
}

pub struct SandboxOutcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl SandboxOutcome {
    pub fn empty() -> Self {
        Self {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }
}

/// Detect which sandbox to use at runtime.
/// Defaults to WASI unless running on Linux with the optional `linux_native` feature enabled.
/// If the env `MAGICRUNE_FORCE_WASM=1` is set, always selects WASI.
pub fn detect_sandbox() -> SandboxKind {
    if std::env::var("MAGICRUNE_FORCE_WASM").ok().as_deref() == Some("1") {
        return SandboxKind::Wasi;
    }

    #[cfg(all(target_os = "linux", feature = "linux_native"))]
    {
        return SandboxKind::Linux;
    }

    // Fallback
    SandboxKind::Wasi
}

// Placeholders for native/wasm sandbox backends (wired in CI later)
pub async fn exec_native(cmd: &str, stdin: &[u8], spec: &SandboxSpec) -> SandboxOutcome {
    #[cfg(all(target_os = "linux", feature = "linux_native"))]
    {
        if let Some(out) = linux_try_exec(cmd, stdin, spec).await {
            return out;
        }
    }
    simple_exec_with_timeout(cmd, stdin, spec).await
}

pub async fn exec_wasm(_wasm_bytes: &[u8], _spec: &SandboxSpec) -> SandboxOutcome {
    // Not executed in local bootstrap. Implemented in CI phase with proper deps.
    SandboxOutcome::empty()
}

#[cfg(all(target_os = "linux", feature = "native_sandbox"))]
fn seccomp_minimal_allow() -> Result<(), String> {
    use libseccomp::*;
    // Note: ScmpError is not available in libseccomp v0.3, using String for errors
    // Default deny
    let mut filter =
        ScmpFilterContext::new_filter(ScmpAction::Errno(1)).map_err(|e| format!("{:?}", e))?;
    let arch = get_api();
    let _ = arch; // touch API to satisfy MSRV lint
    let allow = |f: &mut ScmpFilterContext, sys: ScmpSyscall| -> Result<(), String> {
        f.add_rule(ScmpAction::Allow, sys).map_err(|e| format!("{:?}", e))
    };
    // Essential syscalls
    let mut list = vec![
        ScmpSyscall::from_name("read").unwrap(),
        ScmpSyscall::from_name("write").unwrap(),
        ScmpSyscall::from_name("exit").unwrap(),
        ScmpSyscall::from_name("exit_group").unwrap(),
        ScmpSyscall::from_name("futex")
            .unwrap_or_else(|_| ScmpSyscall::from_name("futex_time64").unwrap()),
        ScmpSyscall::from_name("clock_gettime")
            .unwrap_or_else(|_| ScmpSyscall::from_name("clock_gettime64").unwrap()),
        ScmpSyscall::from_name("clock_nanosleep")
            .unwrap_or_else(|_| ScmpSyscall::from_name("clock_nanosleep_time64").unwrap()),
        ScmpSyscall::from_name("rt_sigaction").unwrap(),
        ScmpSyscall::from_name("rt_sigprocmask").unwrap(),
        ScmpSyscall::from_name("ppoll").unwrap_or_else(|_| ScmpSyscall::from_name("poll").unwrap()),
        ScmpSyscall::from_name("openat").unwrap(),
        ScmpSyscall::from_name("statx").unwrap(),
        ScmpSyscall::from_name("close").unwrap(),
        ScmpSyscall::from_name("mmap").unwrap(),
        ScmpSyscall::from_name("munmap").unwrap(),
        ScmpSyscall::from_name("brk").unwrap(),
        ScmpSyscall::from_name("fstat")
            .unwrap_or_else(|_| ScmpSyscall::from_name("newfstatat").unwrap()),
        ScmpSyscall::from_name("lseek").unwrap(),
        ScmpSyscall::from_name("fcntl").unwrap(),
        ScmpSyscall::from_name("readlinkat")
            .unwrap_or_else(|_| ScmpSyscall::from_name("readlink").unwrap()),
    ];
    // getrandom は緩和時に確実に許可
    let loosen = std::env::var("MAGICRUNE_SECCOMP_LOOSEN").ok().as_deref() == Some("1");
    if loosen {
        for name in ["getrandom", "prlimit64", "setrlimit", "clone3"].iter() {
            if let Ok(sys) = ScmpSyscall::from_name(name) {
                list.push(sys);
            }
        }
        eprintln!(
            "[seccomp] INFO: loosen enabled (added: getrandom, prlimit64, setrlimit, clone3)"
        );
    } else {
        if let Ok(sys) = ScmpSyscall::from_name("getrandom") {
            list.push(sys);
        }
    }
    for s in list.into_iter() {
        allow(&mut filter, s).map_err(|e| format!("{:?}", e))?;
    }
    filter.load().map_err(|e| format!("{:?}", e))?;
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "native_sandbox")))]
#[allow(dead_code)]
fn seccomp_minimal_allow() -> Result<(), String> {
    Err("seccomp not supported in this build".into())
}

// OverlayFS(ro) + tmpfs:/tmp (best-effort). Returns guard on success.
#[cfg(all(target_os = "linux", feature = "linux_native"))]
fn try_enable_overlay_ro() -> anyhow::Result<Option<OverlayGuard>> {
    use nix::{mount, mount::MsFlags, sched::unshare, unistd};
    use std::{fs, path::PathBuf};
    if std::env::var("MAGICRUNE_OVERLAY_RO").ok().as_deref() != Some("1") {
        return Ok(None);
    }
    // 1) new mount namespace
    unshare(nix::sched::CloneFlags::CLONE_NEWNS)
        .map_err(|e| anyhow::anyhow!("unshare(CLONE_NEWNS) failed: {e}"))?;
    // 2) make rprivate
    mount::mount(
        Some("none"),
        "/",
        Option::<&str>::None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        Option::<&str>::None,
    )
    .map_err(|e| anyhow::anyhow!("make-rprivate failed: {e}"))?;
    // 3) scratch
    let pid = std::process::id();
    let scratch = PathBuf::from(format!("/tmp/mr_ovl_{pid}"));
    let lower = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let upper = scratch.join("upper");
    let work = scratch.join("work");
    let root = scratch.join("root");
    fs::create_dir_all(&upper)?;
    fs::create_dir_all(&work)?;
    fs::create_dir_all(&root)?;
    // 4) tmpfs for tmp under scratch
    let tmp_in_root = scratch.join("tmp");
    fs::create_dir_all(&tmp_in_root)?;
    mount::mount(
        Some("tmpfs"),
        tmp_in_root.as_path(),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=64m,mode=1777"),
    )
    .map_err(|e| anyhow::anyhow!("mount tmpfs failed: {e}"))?;
    // 5) overlay mount
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    mount::mount(
        Some("overlay"),
        root.as_path(),
        Some("overlay"),
        MsFlags::empty(),
        Some(opts.as_str()),
    )
    .map_err(|e| anyhow::anyhow!("mount overlay failed: {e}"))?;
    // 6) minimal fs inside root
    let proc_path = root.join("proc");
    fs::create_dir_all(&proc_path).ok();
    let _ = mount::mount(
        Some("proc"),
        proc_path.as_path(),
        Some("proc"),
        MsFlags::empty(),
        Some(""),
    );
    // bind tmp into root
    let root_tmp = root.join("tmp");
    fs::create_dir_all(&root_tmp)?;
    mount::mount(
        Some(tmp_in_root.as_path()),
        root_tmp.as_path(),
        Option::<&str>::None,
        MsFlags::MS_BIND,
        Option::<&str>::None,
    )
    .map_err(|e| anyhow::anyhow!("bind tmp into overlay root failed: {e}"))?;
    // 8) pivot_root (best-effort), fallback to chroot
    let put_old = root.join(".old_root");
    std::fs::create_dir_all(&put_old).ok();
    let pivot_ok = match unistd::pivot_root(&root, &put_old) {
        Ok(_) => {
            let _ = unistd::chdir("/");
            true
        }
        Err(_e) => {
            // fallback to chroot
            if let Err(e) = unistd::chroot(&root) {
                return Err(anyhow::anyhow!("chroot failed after pivot_root fail: {e}"));
            }
            let _ = unistd::chdir("/");
            false
        }
    };
    if pivot_ok {
        // Detach old root
        let _ = mount::umount2("/.old_root", mount::MntFlags::MNT_DETACH);
        let _ = std::fs::remove_dir("/.old_root");
    }
    // 9) remount / ro
    let _ = mount::mount(
        Some("none"),
        "/",
        Option::<&str>::None,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        Option::<&str>::None,
    );
    Ok(Some(OverlayGuard { _scratch: scratch }))
}

#[cfg(not(all(target_os = "linux", feature = "linux_native")))]
#[allow(dead_code)]
fn try_enable_overlay_ro() -> anyhow::Result<Option<()>> {
    Ok(None)
}

#[cfg(all(target_os = "linux", feature = "linux_native"))]
struct OverlayGuard {
    _scratch: std::path::PathBuf,
}
#[cfg(all(target_os = "linux", feature = "linux_native"))]
impl Drop for OverlayGuard {
    fn drop(&mut self) {}
}

// Optional Wasmtime wiring; compiled only when feature `wasm_exec` is enabled (CI).
#[cfg(feature = "wasm_exec")]
pub mod wasm_impl {
    use super::{SandboxOutcome, SandboxSpec};
    use wasmtime::{Config, Engine, Linker, Module, Store};
    use wasmtime_wasi::sync::WasiCtxBuilder;

    pub fn engine() -> Engine {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        cfg.epoch_interruption(true);
        Engine::new(&cfg).expect("engine")
    }

    pub async fn exec_bytes(wasm_bytes: &[u8], _spec: &SandboxSpec) -> SandboxOutcome {
        let engine = engine();
        let mut store = Store::new(&engine, WasiCtxBuilder::new().inherit_stdio().build());
        // Apply resource limits derived from spec
        let fuel = 10_000_000u64; // coarse default fuel; could be derived from wall/cpu
        let _ = store.set_fuel(fuel);
        let module = match Module::from_binary(&engine, wasm_bytes) {
            Ok(m) => m,
            Err(_) => return SandboxOutcome::empty(),
        };
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |cx| cx).ok();
        let instance = match linker.instantiate(&mut store, &module) {
            Ok(i) => i,
            Err(_) => return SandboxOutcome::empty(),
        };
        // Try to call _start if present
        if let Ok(start) = instance.get_typed_func::<(), ()>(&mut store, "_start") {
            let _ = start.call(&mut store, ());
        }
        SandboxOutcome::empty()
    }
}

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

async fn simple_exec_with_timeout(cmd: &str, stdin: &[u8], spec: &SandboxSpec) -> SandboxOutcome {
    let mut command = Command::new("bash");
    // Constrain working directory and env to /tmp
    command.current_dir("/tmp");
    command.env("HOME", "/tmp");
    command.env("TMPDIR", "/tmp");
    // Apply POSIX-style rlimits and optional Linux features only when the
    // linux_native feature is enabled on Linux.
    #[cfg(all(target_os = "linux", feature = "linux_native"))]
    {
        use nix::sys::resource::{setrlimit, Resource};
        // Note: nix v0.29 uses rlim_t directly instead of Rlim type
        use std::os::unix::process::CommandExt;
        let _ = unsafe {
            command.pre_exec(|| {
                // Optional overlayfs(ro) + tmpfs:/tmp (best-effort)
                #[cfg(all(target_os = "linux", feature = "linux_native"))]
                {
                    if std::env::var("MAGICRUNE_OVERLAY_RO").ok().as_deref() == Some("1") {
                        match try_enable_overlay_ro() {
                            Ok(Some(_g)) => {
                                eprintln!("[overlay-ro] enabled (overlay root ro + tmpfs:/tmp)");
                            }
                            Ok(None) => { /* gate off; do nothing */ }
                            Err(e) => {
                                eprintln!("[overlay-ro] WARN: enable failed, fallback: {}", e);
                            }
                        }
                    }
                }
                // CPU time limit (seconds)
                let cpu_secs = (spec.cpu_ms / 1000) as u64;
                if cpu_secs > 0 {
                    let _ = setrlimit(
                        Resource::RLIMIT_CPU,
                        cpu_secs,
                        cpu_secs,
                    );
                }
                // Address space (bytes)
                let mem = (spec.memory_mb as u64) * 1024 * 1024;
                if mem > 0 {
                    let _ = setrlimit(
                        Resource::RLIMIT_AS,
                        mem,
                        mem,
                    );
                }
                // pids
                if spec.pids > 0 {
                    let _ = setrlimit(
                        Resource::RLIMIT_NPROC,
                        spec.pids as u64,
                        spec.pids as u64,
                    );
                }
                // Optional seccomp enable (best-effort) when feature/native and env toggled
                #[cfg(all(target_os = "linux", feature = "native_sandbox"))]
                {
                    if std::env::var("MAGICRUNE_SECCOMP").ok().as_deref() == Some("1") {
                        if let Err(e) = super::seccomp_minimal_allow() {
                            eprintln!("WARN: seccomp enable failed: {} (fallback)", e);
                        }
                    }
                }
                Ok(())
            })
        };
        // Best-effort cgroups v2 (opt-in)
        // TODO: cgroups module is not implemented yet
        /*
        #[cfg(all(target_os = "linux", feature = "linux_native"))]
        if std::env::var("MAGICRUNE_CGROUPS").ok().as_deref() == Some("1") {
            match crate::sandbox::cgroups::try_enable_cgroups(
                spec.cpu_ms,
                spec.memory_mb,
                spec.pids,
            ) {
                Ok(Some(path)) => eprintln!("[cgroups] enabled at {}", path),
                Ok(None) => {}
                Err(e) => eprintln!("[cgroups] WARN: enable failed, fallback: {}", e),
            }
        }
        */
    }
    let mut child = match command
        .arg("-lc")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return SandboxOutcome::empty(),
    };
    if !stdin.is_empty() {
        use std::io::Write as _;
        if let Some(mut sin) = child.stdin.take() {
            let _ = sin.write_all(stdin);
        }
    }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(spec.wall_sec);
    loop {
        if let Ok(Some(_st)) = child.try_wait() {
            let out = match child.wait_with_output() {
                Ok(o) => o,
                Err(_) => return SandboxOutcome::empty(),
            };
            return SandboxOutcome {
                exit_code: out.status.code().unwrap_or(1),
                stdout: out.stdout,
                stderr: out.stderr,
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return SandboxOutcome {
                exit_code: 20,
                stdout: Vec::new(),
                stderr: b"timeout".to_vec(),
            };
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(all(target_os = "linux", feature = "linux_native"))]
async fn linux_try_exec(cmd: &str, stdin: &[u8], spec: &SandboxSpec) -> Option<SandboxOutcome> {
    use nix::sched::{unshare, CloneFlags};
    // Try a stronger isolation first (include NEWNET/NEWUSER when allowed),
    // fall back to a minimal set if kernel/permissions reject.
    let attempts: &[CloneFlags] = &[
        CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWNET
            | CloneFlags::CLONE_NEWUSER,
        CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWNET,
        CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS,
    ];
    let mut ok = false;
    for flags in attempts {
        if unshare(*flags).is_ok() {
            ok = true;
            break;
        }
    }
    if !ok {
        return None;
    }
    let out = simple_exec_with_timeout(cmd, stdin, spec).await;
    Some(out)
}
