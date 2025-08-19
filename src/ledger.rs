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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_record_creation() {
        let record = RunRecord {
            run_id: "test-123".to_string(),
            verdict: "safe".to_string(),
            risk_score: 25,
            exit_code: 0,
        };
        
        assert_eq!(record.run_id, "test-123");
        assert_eq!(record.verdict, "safe");
        assert_eq!(record.risk_score, 25);
        assert_eq!(record.exit_code, 0);
    }

    #[test]
    fn test_run_record_clone() {
        let record = RunRecord {
            run_id: "test-456".to_string(),
            verdict: "risky".to_string(),
            risk_score: 75,
            exit_code: 1,
        };
        
        let cloned = record.clone();
        assert_eq!(cloned.run_id, record.run_id);
        assert_eq!(cloned.verdict, record.verdict);
        assert_eq!(cloned.risk_score, record.risk_score);
        assert_eq!(cloned.exit_code, record.exit_code);
    }

    #[test]
    fn test_in_memory_ledger_new() {
        let ledger = InMemoryLedger::new();
        assert!(ledger.get("non-existent").is_none());
    }

    #[test]
    fn test_in_memory_ledger_put_and_get() {
        let ledger = InMemoryLedger::new();
        let record = RunRecord {
            run_id: "test-789".to_string(),
            verdict: "safe".to_string(),
            risk_score: 10,
            exit_code: 0,
        };
        
        ledger.put(record.clone());
        
        let retrieved = ledger.get("test-789");
        assert!(retrieved.is_some());
        
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.run_id, "test-789");
        assert_eq!(retrieved.verdict, "safe");
        assert_eq!(retrieved.risk_score, 10);
        assert_eq!(retrieved.exit_code, 0);
    }

    #[test]
    fn test_in_memory_ledger_multiple_records() {
        let ledger = InMemoryLedger::new();
        
        let record1 = RunRecord {
            run_id: "run-1".to_string(),
            verdict: "safe".to_string(),
            risk_score: 5,
            exit_code: 0,
        };
        
        let record2 = RunRecord {
            run_id: "run-2".to_string(),
            verdict: "risky".to_string(),
            risk_score: 85,
            exit_code: 2,
        };
        
        ledger.put(record1.clone());
        ledger.put(record2.clone());
        
        assert!(ledger.get("run-1").is_some());
        assert!(ledger.get("run-2").is_some());
        assert!(ledger.get("run-3").is_none());
        
        let r1 = ledger.get("run-1").unwrap();
        assert_eq!(r1.verdict, "safe");
        
        let r2 = ledger.get("run-2").unwrap();
        assert_eq!(r2.verdict, "risky");
    }

    #[test]
    fn test_in_memory_ledger_overwrite() {
        let ledger = InMemoryLedger::new();
        
        let record1 = RunRecord {
            run_id: "test-id".to_string(),
            verdict: "safe".to_string(),
            risk_score: 10,
            exit_code: 0,
        };
        
        let record2 = RunRecord {
            run_id: "test-id".to_string(),
            verdict: "risky".to_string(),
            risk_score: 90,
            exit_code: 1,
        };
        
        ledger.put(record1);
        ledger.put(record2);
        
        let retrieved = ledger.get("test-id").unwrap();
        assert_eq!(retrieved.verdict, "risky");
        assert_eq!(retrieved.risk_score, 90);
        assert_eq!(retrieved.exit_code, 1);
    }
}
