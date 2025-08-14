use crate::ports::{env::EnvError, EnvironmentPort, TimePort};
use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct StdTimeAdapter;

#[async_trait::async_trait]
impl TimePort for StdTimeAdapter {
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    async fn sleep(&self, duration: Duration) {
        use std::thread;
        thread::sleep(duration);
    }
}

pub struct StdEnvAdapter;

impl EnvironmentPort for StdEnvAdapter {
    fn get_var(&self, key: &str) -> Result<String, EnvError> {
        std::env::var(key).map_err(|_| EnvError::NotFound(key.to_string()))
    }

    fn set_var(&self, key: &str, value: &str) {
        std::env::set_var(key, value)
    }

    fn remove_var(&self, key: &str) {
        std::env::remove_var(key)
    }

    fn current_dir(&self) -> Result<String, EnvError> {
        std::env::current_dir()
            .map_err(|e| EnvError::InvalidValue("current_dir".to_string(), e.to_string()))
            .and_then(|p| {
                p.to_str()
                    .ok_or_else(|| {
                        EnvError::InvalidValue(
                            "current_dir".to_string(),
                            "invalid UTF-8".to_string(),
                        )
                    })
                    .map(|s| s.to_string())
            })
    }

    fn args(&self) -> Vec<String> {
        std::env::args().collect()
    }
}
