use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum AuditEvent {
    CommandExecution {
        command: String,
        exit_code: i32,
        duration_ms: u64,
    },
    FileRead {
        path: String,
        size: u64,
    },
    FileWrite {
        path: String,
        size: u64,
    },
    FileDelete {
        path: String,
    },
    NetworkConnection {
        host: String,
        port: u16,
        protocol: String,
    },
    ProcessSpawn {
        command: String,
        pid: u32,
    },
    PrivilegeEscalation {
        method: String,
    },
    SandboxEscape {
        method: String,
    },
    SandboxExecution {
        profile: String,
        restrictions: Vec<String>,
    },
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditEvent::CommandExecution { command, exit_code, duration_ms } => {
                write!(f, "Command '{}' exited with code {} ({}ms)", command, exit_code, duration_ms)
            }
            AuditEvent::FileRead { path, size } => {
                write!(f, "Read file '{}' ({} bytes)", path, size)
            }
            AuditEvent::FileWrite { path, size } => {
                write!(f, "Wrote file '{}' ({} bytes)", path, size)
            }
            AuditEvent::FileDelete { path } => {
                write!(f, "Deleted file '{}'", path)
            }
            AuditEvent::NetworkConnection { host, port, protocol } => {
                write!(f, "Network connection to {}:{} ({})", host, port, protocol)
            }
            AuditEvent::ProcessSpawn { command, pid } => {
                write!(f, "Spawned process '{}' (PID: {})", command, pid)
            }
            AuditEvent::PrivilegeEscalation { method } => {
                write!(f, "Privilege escalation attempt: {}", method)
            }
            AuditEvent::SandboxEscape { method } => {
                write!(f, "Sandbox escape attempt: {}", method)
            }
            AuditEvent::SandboxExecution { profile, restrictions } => {
                write!(f, "Sandbox execution with profile '{}' and {} restrictions", 
                    profile, restrictions.len())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub origin: String,
    pub policy_version: u32,
    pub event: AuditEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

pub struct AuditLogger {
    log_dir: PathBuf,
    current_file: Option<PathBuf>,
    actor: String,
}

impl AuditLogger {
    pub fn new(log_dir: PathBuf, actor: String) -> Result<Self> {
        if !log_dir.exists() {
            fs::create_dir_all(&log_dir)?;
        }
        
        Ok(Self {
            log_dir,
            current_file: None,
            actor,
        })
    }
    
    pub fn log_event(&mut self, event: AuditEvent, origin: &str, policy_version: u32) -> Result<()> {
        let log_entry = AuditLog {
            timestamp: Utc::now(),
            actor: self.actor.clone(),
            origin: origin.to_string(),
            policy_version,
            event: event.clone(),
            metadata: None,
        };
        
        self.write_log_entry(&log_entry)?;
        debug!("Audit event logged: {}", event);
        
        Ok(())
    }
    
    pub fn log_event_with_metadata(
        &mut self,
        event: AuditEvent,
        origin: &str,
        policy_version: u32,
        metadata: serde_json::Value,
    ) -> Result<()> {
        let log_entry = AuditLog {
            timestamp: Utc::now(),
            actor: self.actor.clone(),
            origin: origin.to_string(),
            policy_version,
            event: event.clone(),
            metadata: Some(metadata),
        };
        
        self.write_log_entry(&log_entry)?;
        debug!("Audit event logged with metadata: {}", event);
        
        Ok(())
    }
    
    fn write_log_entry(&mut self, entry: &AuditLog) -> Result<()> {
        let log_file = self.get_or_create_log_file()?;
        
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&log_file)?;
        
        let json = serde_json::to_string(entry)?;
        writeln!(file, "{}", json)?;
        
        Ok(())
    }
    
    fn get_or_create_log_file(&mut self) -> Result<PathBuf> {
        let now = Utc::now();
        let filename = format!("audit-{}.ndjson", now.format("%Y%m%d"));
        let log_file = self.log_dir.join(&filename);
        
        if self.current_file.as_ref() != Some(&log_file) {
            self.current_file = Some(log_file.clone());
        }
        
        Ok(log_file)
    }
}

pub fn parse_audit_log<P: AsRef<Path>>(path: P) -> Result<Vec<AuditLog>> {
    let content = fs::read_to_string(path)?;
    let mut logs = Vec::new();
    
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        
        match serde_json::from_str::<AuditLog>(line) {
            Ok(log) => logs.push(log),
            Err(e) => {
                error!("Failed to parse audit log line: {}", e);
            }
        }
    }
    
    Ok(logs)
}

pub async fn cleanup_old_logs(log_dir: &Path, retention_days: u32) -> Result<()> {
    let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
    
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.extension().and_then(|s| s.to_str()) == Some("ndjson") {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    let modified: DateTime<Utc> = modified.into();
                    if modified < cutoff {
                        debug!("Removing old audit log: {}", path.display());
                        fs::remove_file(path)?;
                    }
                }
            }
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_audit_logger() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let mut logger = AuditLogger::new(
            temp_dir.path().to_path_buf(),
            "test_user".to_string(),
        )?;
        
        logger.log_event(
            AuditEvent::CommandExecution {
                command: "echo test".to_string(),
                exit_code: 0,
                duration_ms: 10,
            },
            "L1",
            1,
        )?;
        
        // Verify log file was created
        let entries: Vec<_> = fs::read_dir(temp_dir.path())?.collect();
        assert_eq!(entries.len(), 1);
        
        Ok(())
    }
    
    #[test]
    fn test_parse_audit_log() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let log_file = temp_dir.path().join("test.ndjson");
        
        let log1 = AuditLog {
            timestamp: Utc::now(),
            actor: "test".to_string(),
            origin: "L1".to_string(),
            policy_version: 1,
            event: AuditEvent::FileRead {
                path: "/tmp/test.txt".to_string(),
                size: 100,
            },
            metadata: None,
        };
        
        let json1 = serde_json::to_string(&log1)?;
        fs::write(&log_file, format!("{}\n", json1))?;
        
        let parsed = parse_audit_log(&log_file)?;
        assert_eq!(parsed.len(), 1);
        
        Ok(())
    }
}