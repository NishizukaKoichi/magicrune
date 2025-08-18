#[cfg(target_os = "linux")]
#[test]
fn cgroups_opt_in_smoke() {
    // Only run when explicitly requested; otherwise skip.
    if std::env::var("MAGICRUNE_REQUIRE_CGROUPS").ok().as_deref() != Some("1") {
        eprintln!("cgroups smoke skipped");
        return;
    }
    let st = std::process::Command::new("cargo")
        .args(["run","--bin","magicrune","--","exec","-f","samples/ok.json"]) 
        .env("MAGICRUNE_CGROUPS","1")
        .status().expect("run magicrune");
    assert!(st.success());
}

