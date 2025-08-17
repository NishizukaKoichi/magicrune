#[cfg(feature = "jet")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "127.0.0.1:4222".to_string());
    let subject = std::env::var("NATS_REQ_SUBJ").unwrap_or_else(|_| "run.req.default".to_string());
    let nc = bootstrapped::jet::jet_impl::connect(&format!("nats://{}", url)).await?;
    let mut sub = nc.subscribe(subject.clone()).await?;
    while let Some(msg) = sub.next().await {
        let id = bootstrapped::jet::compute_msg_id(&msg.payload);
        // Dedup: NATS server enforces via Nats-Msg-Id header; we simply log.
        eprintln!("recv id={}", id);
        // Normally: execute sandboxed and publish to run.res.$RUN_ID
    }
    Ok(())
}

#[cfg(not(feature = "jet"))]
fn main() {
    eprintln!("jet feature not enabled");
}
