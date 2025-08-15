use async_nats::jetstream::context::Context;
use async_nats::{Client, HeaderMap};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::grader;
use crate::schema::{PolicyDoc, SpellRequest, SpellResult};

pub async fn run(nats_url: &str) -> anyhow::Result<()> {
    let client: Client = async_nats::connect(nats_url).await?;
    // JetStream context (optional best-effort)
    let _js: Context = async_nats::jetstream::new(client.clone());

    let mut sub = client.subscribe("run.req.>").await?;
    while let Some(msg) = sub.next().await {
        // Compute Msg-Id = SHA-256(request)
        let mut hasher = Sha256::new();
        hasher.update(&msg.payload);
        let req_hash = hasher.finalize();
        let msg_id = hex::encode(req_hash);

        // Parse request
        let req: SpellRequest = match serde_json::from_slice(&msg.payload) {
            Ok(v) => v,
            Err(_) => {
                // ignore malformed
                continue;
            }
        };
        // Load default policy (best-effort)
        let policy: PolicyDoc = PolicyDoc { version: 1, grading: None };
        let outcome = grader::grade(&req, &policy);

        // Deterministic run_id (reuse msg_id prefix)
        let run_id = format!("r_{}", &msg_id[..20]);
        let result = SpellResult {
            run_id: run_id.clone(),
            verdict: outcome.verdict.clone(),
            risk_score: outcome.risk_score,
            exit_code: match outcome.verdict.as_str() { "green" => 0, "yellow" => 10, "red" => 20, _ => 4 },
            duration_ms: 0,
            stdout_trunc: false,
            sbom_attestation: "file://sbom.spdx.json.sig".to_string(),
        };
        let body = match serde_json::to_vec(&result) { Ok(b) => b, Err(_) => continue };

        // Publish to run.res.$RUN_ID with Nats-Msg-Id
        let mut headers = HeaderMap::new();
        headers.append("Nats-Msg-Id", msg_id.clone());
        let subject = format!("run.res.{run_id}");
        let _ = client.publish_with_headers(subject, headers, body.into()).await;
        // small yield to avoid busy loop
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    Ok(())
}
