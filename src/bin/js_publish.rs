#[cfg(feature = "jet")]
mod app {
    use bootstrapped::jet::{compute_msg_id, jet_impl};
    use futures_util::StreamExt;
    use serde_json::Value;
    use std::str::FromStr as _;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    }

    #[tokio::main]
    pub async fn main() -> anyhow::Result<()> {
        // Args: <file.json> [subject]
        let mut args = std::env::args().skip(1);
        let file = args.next().unwrap_or_else(|| "samples/ok.json".to_string());
        let subject = args
            .next()
            .unwrap_or_else(|| "run.req.default".to_string());

        let url = std::env::var("NATS_URL").unwrap_or_else(|_| "127.0.0.1:4222".to_string());
        let nc = jet_impl::connect(&format!("nats://{}", url))
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let payload = std::fs::read(&file)?;
        // Compute run_id the same way as consumer: hash(payload + seed_le)
        let seed_le = {
            let v: Value = serde_json::from_slice(&payload).unwrap_or(Value::Null);
            let seed = v
                .get("seed")
                .and_then(|x| x.as_u64())
                .unwrap_or(0u64)
                .to_le_bytes()
                .to_vec();
            seed
        };
        let mut all = payload.clone();
        all.extend_from_slice(&seed_le);
        let run_id = format!("r_{}", sha256_hex(&all));

        // Publish request with Nats-Msg-Id header (ensure stream exists first)
        {
            use async_nats::jetstream::{self, stream::{Config, RetentionPolicy, StorageType}};
            let js = jetstream::new(nc.clone());
            let name = std::env::var("NATS_STREAM").unwrap_or_else(|_| "RUN".to_string());
            let cfg = Config {
                name: name.clone(),
                subjects: vec![subject.clone()],
                retention: RetentionPolicy::Limits,
                max_consumers: -1,
                max_messages: -1,
                max_bytes: -1,
                duplicate_window: std::time::Duration::from_secs(120),
                storage: StorageType::File,
                ..Default::default()
            };
            if js.get_stream(&name).await.is_err() {
                let _ = js.create_stream(cfg).await;
            }

            let mut headers = async_nats::header::HeaderMap::new();
            let id = compute_msg_id(&payload);
            headers.insert("Nats-Msg-Id", async_nats::header::HeaderValue::from_str(&id)?);
            js.publish_with_headers(subject.clone(), headers, payload.clone().into()).await?;
        }

        // Wait for response on run.res.<run_id>
        let res_subject = format!("run.res.{}", run_id);
        let mut sub = nc.subscribe(res_subject.clone()).await?;
        let to_secs = std::env::var("JS_PUBLISH_TIMEOUT_SEC")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5);
        let got = tokio::time::timeout(std::time::Duration::from_secs(to_secs), sub.next())
            .await
            .map_err(|_| anyhow::anyhow!("timeout waiting for {}", res_subject))?;
        if let Some(m) = got {
            println!("{}", String::from_utf8_lossy(&m.payload));
            // Send ack-ack confirmation
            let ack_subject = format!("run.ack.{}", run_id);
            let _ = nc.publish(ack_subject, b"ok".to_vec().into()).await;
        } else {
            anyhow::bail!("subscription ended prematurely");
        }
        Ok(())
    }
}

#[cfg(feature = "jet")]
fn main() {
    app::main().unwrap();
}

#[cfg(not(feature = "jet"))]
fn main() {
    eprintln!("jet feature not enabled");
}
