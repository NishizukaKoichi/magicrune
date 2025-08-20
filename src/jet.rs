// JetStream placeholders (no network in local env). CIで依存を導入後に差し替え可能。

pub struct JsConfig {
    pub subject_req: String,
}

pub struct JsResult<T> {
    pub ok: bool,
    pub value: Option<T>,
    pub err: Option<String>,
}

pub fn compute_msg_id(payload: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let hash = hasher.finalize();
    format!("{:x}", hash)
}

pub async fn send_request(_cfg: &JsConfig, _bytes: &[u8]) -> JsResult<()> {
    JsResult {
        ok: false,
        value: None,
        err: Some("network disabled".into()),
    }
}

pub async fn publish_result(_subject: &str, _bytes: &[u8]) -> JsResult<()> {
    JsResult {
        ok: false,
        value: None,
        err: Some("network disabled".into()),
    }
}

// Optional async-nats implementation; compiled only when feature `jet` is enabled (CI).
#[cfg(feature = "jet")]
pub mod jet_impl {
    use super::compute_msg_id;
    use async_nats::header::HeaderMap;
    use async_nats::Client;
    use std::error::Error as StdError;
    use std::str::FromStr as _;

    pub async fn connect(url: &str) -> Result<Client, Box<dyn StdError + Send + Sync>> {
        async_nats::connect(url)
            .await
            .map_err(|e| Box::new(e) as Box<dyn StdError + Send + Sync>)
    }

    pub async fn publish_req(
        nc: &Client,
        subject: &str,
        req: &[u8],
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let mut headers = HeaderMap::new();
        let id = compute_msg_id(req);
        headers.insert(
            "Nats-Msg-Id",
            async_nats::header::HeaderValue::from_str(&id).unwrap(),
        );
        nc.publish_with_headers(subject.to_string(), headers, req.to_vec().into())
            .await
            .map_err(|e| Box::new(e) as Box<dyn StdError + Send + Sync>)?;
        Ok(())
    }

    pub async fn publish_res(
        nc: &Client,
        subject: &str,
        res: &[u8],
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        nc.publish(subject.to_string(), res.to_vec().into())
            .await
            .map_err(|e| Box::new(e) as Box<dyn StdError + Send + Sync>)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_js_config_creation() {
        let config = JsConfig {
            subject_req: "test.subject".to_string(),
        };
        assert_eq!(config.subject_req, "test.subject");
    }

    #[test]
    fn test_js_result_ok() {
        let result: JsResult<i32> = JsResult {
            ok: true,
            value: Some(42),
            err: None,
        };
        assert!(result.ok);
        assert_eq!(result.value, Some(42));
        assert!(result.err.is_none());
    }

    #[test]
    fn test_js_result_error() {
        let result: JsResult<i32> = JsResult {
            ok: false,
            value: None,
            err: Some("error message".to_string()),
        };
        assert!(!result.ok);
        assert!(result.value.is_none());
        assert_eq!(result.err, Some("error message".to_string()));
    }

    #[test]
    fn test_compute_msg_id() {
        let payload1 = b"test payload";
        let payload2 = b"test payload";
        let payload3 = b"different payload";

        let id1 = compute_msg_id(payload1);
        let id2 = compute_msg_id(payload2);
        let id3 = compute_msg_id(payload3);

        // Same payload should produce same ID
        assert_eq!(id1, id2);
        // Different payload should produce different ID
        assert_ne!(id1, id3);
        // ID should be hex string
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_msg_id_empty() {
        let id = compute_msg_id(b"");
        // Should produce valid hash even for empty input
        assert!(!id.is_empty());
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_send_request_disabled() {
        let config = JsConfig {
            subject_req: "test.subject".to_string(),
        };
        let result = send_request(&config, b"test data").await;

        assert!(!result.ok);
        assert!(result.value.is_none());
        assert_eq!(result.err, Some("network disabled".to_string()));
    }

    #[tokio::test]
    async fn test_publish_result_disabled() {
        let result = publish_result("test.subject", b"test data").await;

        assert!(!result.ok);
        assert!(result.value.is_none());
        assert_eq!(result.err, Some("network disabled".to_string()));
    }
}
