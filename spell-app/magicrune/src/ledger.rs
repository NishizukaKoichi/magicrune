use anyhow::Result;
use async_trait::async_trait;
use rusqlite::{params, Connection};
use std::path::Path;
use crate::schema::{SpellRequest, SpellResult};

#[async_trait]
pub trait Ledger: Send + Sync {
    async fn store_request(&self, request: &SpellRequest) -> Result<String>;
    async fn store_result(&self, result: &SpellResult) -> Result<()>;
    async fn get_request(&self, request_id: &str) -> Result<Option<SpellRequest>>;
    async fn get_result(&self, run_id: &str) -> Result<Option<SpellResult>>;
    async fn check_duplicate(&self, request_id: &str) -> Result<Option<String>>;
}

pub struct LocalLedger {
    db_path: String,
}

impl LocalLedger {
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref().to_string_lossy().to_string();
        let conn = Connection::open(&db_path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS requests (
                request_id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS results (
                run_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (request_id) REFERENCES requests (request_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_request_id ON results (request_id)",
            [],
        )?;

        Ok(Self { db_path })
    }

    fn get_conn(&self) -> Result<Connection> {
        Ok(Connection::open(&self.db_path)?)
    }
}

#[async_trait]
impl Ledger for LocalLedger {
    async fn store_request(&self, request: &SpellRequest) -> Result<String> {
        let request_id = request.generate_id();
        let content = serde_json::to_string(request)?;
        
        let conn = self.get_conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO requests (request_id, content) VALUES (?1, ?2)",
            params![&request_id, &content],
        )?;
        
        Ok(request_id)
    }

    async fn store_result(&self, result: &SpellResult) -> Result<()> {
        let content = serde_json::to_string(result)?;
        let request_id = result.run_id.split('_').last()
            .ok_or_else(|| anyhow::anyhow!("Invalid run_id format"))?;
        
        let conn = self.get_conn()?;
        conn.execute(
            "INSERT INTO results (run_id, request_id, content) VALUES (?1, ?2, ?3)",
            params![&result.run_id, request_id, &content],
        )?;
        
        Ok(())
    }

    async fn get_request(&self, request_id: &str) -> Result<Option<SpellRequest>> {
        let conn = self.get_conn()?;
        let mut stmt = conn.prepare("SELECT content FROM requests WHERE request_id = ?1")?;
        
        let result = stmt.query_row(params![request_id], |row| {
            let content: String = row.get(0)?;
            Ok(content)
        });
        
        match result {
            Ok(content) => Ok(Some(serde_json::from_str(&content)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_result(&self, run_id: &str) -> Result<Option<SpellResult>> {
        let conn = self.get_conn()?;
        let mut stmt = conn.prepare("SELECT content FROM results WHERE run_id = ?1")?;
        
        let result = stmt.query_row(params![run_id], |row| {
            let content: String = row.get(0)?;
            Ok(content)
        });
        
        match result {
            Ok(content) => Ok(Some(serde_json::from_str(&content)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn check_duplicate(&self, request_id: &str) -> Result<Option<String>> {
        let conn = self.get_conn()?;
        let mut stmt = conn.prepare(
            "SELECT run_id FROM results WHERE request_id = ?1 ORDER BY created_at DESC LIMIT 1"
        )?;
        
        let result = stmt.query_row(params![request_id], |row| {
            let run_id: String = row.get(0)?;
            Ok(run_id)
        });
        
        match result {
            Ok(run_id) => Ok(Some(run_id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_local_ledger() -> Result<()> {
        let temp_file = NamedTempFile::new()?;
        let ledger = LocalLedger::new(temp_file.path())?;
        
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
        
        let request_id = ledger.store_request(&request).await?;
        assert!(!request_id.is_empty());
        
        let retrieved = ledger.get_request(&request_id).await?;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().cmd, "echo test");
        
        Ok(())
    }
}