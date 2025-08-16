#[cfg(all(feature = "jet", not(target_env = "musl")))]
mod jet_tests {
    use tokio::time::{timeout, Duration};

    #[tokio::test(flavor = "current_thread")] 
    async fn nats_connect_smoke() {
        let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
        let fut = async_nats::connect(&url);
        let conn = timeout(Duration::from_secs(5), fut).await.expect("timeout");
        assert!(conn.is_ok(), "failed to connect to NATS at {}", url);
    }
}

