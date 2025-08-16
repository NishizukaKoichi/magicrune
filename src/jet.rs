// JetStream placeholders (no network in local env). CIで依存を導入後に差し替え可能。

pub struct JsConfig {
    pub subject_req: String,
}

pub struct JsResult<T> {
    pub ok: bool,
    pub value: Option<T>,
    pub err: Option<String>,
}

pub async fn send_request(_cfg: &JsConfig, _bytes: &[u8]) -> JsResult<()> {
    JsResult { ok: false, value: None, err: Some("network disabled".into()) }
}

pub async fn publish_result(_subject: &str, _bytes: &[u8]) -> JsResult<()> {
    JsResult { ok: false, value: None, err: Some("network disabled".into()) }
}

// Optional async-nats implementation; compiled only when feature `jet` is enabled (CI).
#[cfg(feature = "jet")]
pub mod jet_impl {
    use async_nats::Client;

    pub async fn connect(url: &str) -> Result<Client, async_nats::ConnectError> {
        async_nats::connect(url).await
    }

    pub async fn publish_req(nc: &Client, subject: &str, req: &[u8]) -> Result<(), async_nats::Error> {
        // NOTE: Dedup header (Nats-Msg-Id) will be added in a later step if needed.
        nc.publish(subject.to_string(), req.to_vec()).await
    }

    pub async fn publish_res(nc: &Client, subject: &str, res: &[u8]) -> Result<(), async_nats::Error> {
        nc.publish(subject.to_string(), res.to_vec()).await
    }
}
