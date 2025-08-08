use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::schema::{SpellRequest, SpellResult, Verdict};

#[async_trait]
pub trait Ledger: Send + Sync {
    async fn record_run(&self, request: &SpellRequest, result: &SpellResult) -> Result<()>;
    async fn get_run(&self, run_id: &str) -> Result<Option<(SpellRequest, SpellResult)>>;
    async fn get_runs_by_verdict(&self, verdict: Verdict, limit: usize) -> Result<Vec<SpellResult>>;
}

pub struct LocalLedger {
    db_path: String,
}

impl LocalLedger {
    pub fn new(db_path: impl Into<String>) -> Result<Self> {
        let ledger = Self {
            db_path: db_path.into(),
        };
        ledger.init_db()?;
        Ok(ledger)
    }

    fn init_db(&self) -> Result<()> {
        let conn = Connection::open(&self.db_path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                request_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verdict ON runs(verdict)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_created_at ON runs(created_at)",
            [],
        )?;

        Ok(())
    }

    fn with_conn<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Connection) -> Result<R>,
    {
        let conn = Connection::open(&self.db_path)?;
        f(&conn)
    }
}

#[async_trait]
impl Ledger for LocalLedger {
    async fn record_run(&self, request: &SpellRequest, result: &SpellResult) -> Result<()> {
        let request_json = serde_json::to_string(request)?;
        let result_json = serde_json::to_string(result)?;
        let run_id = result.run_id.clone();
        let verdict_str = match result.verdict {
            Verdict::Green => "green",
            Verdict::Yellow => "yellow",
            Verdict::Red => "red",
        };
        let created_at = Utc::now().to_rfc3339();

        let db_path = self.db_path.clone();
        let risk_score = result.risk_score;
        
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            conn.execute(
                "INSERT INTO runs (run_id, request_json, result_json, verdict, risk_score, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &run_id,
                    &request_json,
                    &result_json,
                    verdict_str,
                    risk_score,
                    created_at
                ],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        Ok(())
    }

    async fn get_run(&self, run_id: &str) -> Result<Option<(SpellRequest, SpellResult)>> {
        let db_path = self.db_path.clone();
        let run_id = run_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT request_json, result_json FROM runs WHERE run_id = ?1"
            )?;
            
            let result: Option<(String, String)> = stmt.query_row(params![run_id], |row| {
                let request_json: String = row.get(0)?;
                let result_json: String = row.get(1)?;
                Ok((request_json, result_json))
            }).optional()?;

            match result {
                Some((request_json, result_json)) => {
                    let request: SpellRequest = serde_json::from_str(&request_json)?;
                    let result: SpellResult = serde_json::from_str(&result_json)?;
                    Ok(Some((request, result)))
                }
                None => Ok(None),
            }
        })
        .await?
    }

    async fn get_runs_by_verdict(&self, verdict: Verdict, limit: usize) -> Result<Vec<SpellResult>> {
        let verdict_str = match verdict {
            Verdict::Green => "green",
            Verdict::Yellow => "yellow",
            Verdict::Red => "red",
        };
        
        let db_path = self.db_path.clone();
        let verdict_str = verdict_str.to_string();
        
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT result_json FROM runs WHERE verdict = ?1 
                 ORDER BY created_at DESC LIMIT ?2"
            )?;
            
            let results = stmt.query_map(params![verdict_str, limit], |row| {
                let result_json: String = row.get(0)?;
                Ok(result_json)
            })?
            .collect::<Result<Vec<_>, _>>()?;

            let mut spell_results = Vec::new();
            for json in results {
                let result: SpellResult = serde_json::from_str(&json)?;
                spell_results.push(result);
            }

            Ok(spell_results)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_local_ledger() -> Result<()> {
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path().join("test.db");
        let ledger = LocalLedger::new(db_path.to_str().unwrap())?;

        let request = SpellRequest {
            cmd: "echo test".to_string(),
            stdin: String::new(),
            env: Default::default(),
            files: vec![],
            policy_id: "default".to_string(),
            timeout_sec: 15,
            allow_net: vec![],
            allow_fs: vec![],
        };

        let result = SpellResult {
            run_id: "r_01H8C6W6PS6KD5R463JTDY7G9".to_string(),
            verdict: Verdict::Green,
            risk_score: 10,
            exit_code: 0,
            duration_ms: 100,
            stdout: Some("test\n".to_string()),
            stderr: None,
            stdout_trunc: false,
            stderr_trunc: false,
            sbom_attestation: None,
            error: None,
            quarantine_path: None,
        };

        ledger.record_run(&request, &result).await?;

        let retrieved = ledger.get_run(&result.run_id).await?;
        assert!(retrieved.is_some());

        let (req, res) = retrieved.unwrap();
        assert_eq!(req.cmd, request.cmd);
        assert_eq!(res.run_id, result.run_id);

        let green_runs = ledger.get_runs_by_verdict(Verdict::Green, 10).await?;
        assert_eq!(green_runs.len(), 1);
        assert_eq!(green_runs[0].run_id, result.run_id);

        Ok(())
    }
}