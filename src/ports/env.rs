use thiserror::Error;

#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Error, Debug)]
pub enum EnvError {
    #[error("Environment variable not found: {0}")]
    NotFound(String),
    #[error("Invalid value for environment variable {0}: {1}")]
    InvalidValue(String, String),
}

pub trait EnvironmentPort: Send + Sync {
    fn get_var(&self, key: &str) -> Result<String, EnvError>;
    fn set_var(&self, key: &str, value: &str);
    fn remove_var(&self, key: &str);
    fn current_dir(&self) -> Result<String, EnvError>;
    fn args(&self) -> Vec<String>;
}
