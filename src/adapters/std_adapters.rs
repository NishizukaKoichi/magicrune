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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_std_time_adapter_now_millis() {
        let adapter = StdTimeAdapter;
        let millis1 = adapter.now_millis();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let millis2 = adapter.now_millis();

        assert!(millis2 > millis1);
        assert!(millis1 > 0);
    }

    #[test]
    fn test_std_time_adapter_now_secs() {
        let adapter = StdTimeAdapter;
        let secs = adapter.now_secs();

        // Should be a reasonable timestamp (after year 2020)
        assert!(secs > 1577836800); // Jan 1, 2020
    }

    #[tokio::test]
    async fn test_std_time_adapter_sleep() {
        let adapter = StdTimeAdapter;
        let start = std::time::Instant::now();
        adapter.sleep(Duration::from_millis(50)).await;
        let elapsed = start.elapsed();

        // Should have slept for at least 50ms
        assert!(elapsed >= Duration::from_millis(50));
    }

    #[test]
    fn test_std_env_adapter_var_operations() {
        let adapter = StdEnvAdapter;
        let test_key = "TEST_MAGICRUNE_VAR";
        let test_value = "test_value_123";

        // Test set_var
        adapter.set_var(test_key, test_value);

        // Test get_var
        let result = adapter.get_var(test_key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_value);

        // Test remove_var
        adapter.remove_var(test_key);
        let result = adapter.get_var(test_key);
        assert!(result.is_err());
        match result.unwrap_err() {
            EnvError::NotFound(key) => assert_eq!(key, test_key),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[test]
    fn test_std_env_adapter_current_dir() {
        let adapter = StdEnvAdapter;
        let result = adapter.current_dir();

        assert!(result.is_ok());
        let dir = result.unwrap();
        assert!(!dir.is_empty());
        // Should be an absolute path
        assert!(dir.starts_with('/') || dir.contains(':'));
    }

    #[test]
    fn test_std_env_adapter_args() {
        let adapter = StdEnvAdapter;
        let args = adapter.args();

        // Should at least contain the program name
        assert!(!args.is_empty());
    }

    #[test]
    fn test_std_env_adapter_get_nonexistent_var() {
        let adapter = StdEnvAdapter;
        let result = adapter.get_var("DEFINITELY_NONEXISTENT_VAR_MAGICRUNE_TEST");

        assert!(result.is_err());
        match result.unwrap_err() {
            EnvError::NotFound(key) => {
                assert_eq!(key, "DEFINITELY_NONEXISTENT_VAR_MAGICRUNE_TEST")
            }
            _ => panic!("Expected NotFound error"),
        }
    }
}
