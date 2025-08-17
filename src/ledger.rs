#[derive(Debug, Clone)]
pub struct RunRecord {
    pub run_id: String,
    pub verdict: String,
    pub risk_score: u32,
    pub exit_code: i32,
}

#[allow(async_fn_in_trait)]
pub trait Ledger: Send + Sync {
    fn put(&self, rec: RunRecord);
    fn get(&self, run_id: &str) -> Option<RunRecord>;
}

#[derive(Default, Debug)]
pub struct InMemoryLedger {
    inner: std::sync::Mutex<std::collections::HashMap<String, RunRecord>>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Ledger for InMemoryLedger {
    fn put(&self, rec: RunRecord) {
        let mut g = self.inner.lock().unwrap();
        g.insert(rec.run_id.clone(), rec);
    }
    fn get(&self, run_id: &str) -> Option<RunRecord> {
        let g = self.inner.lock().unwrap();
        g.get(run_id).cloned()
    }
}

