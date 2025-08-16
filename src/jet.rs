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
