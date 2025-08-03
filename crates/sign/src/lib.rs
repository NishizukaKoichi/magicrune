use anyhow::{Context, Result};
use magicrune_policy::SigningConfig;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};
use base64::{Engine as _, engine::general_purpose};
use tempfile;

pub fn verify_command_signature(
    command: &str,
    signature_path: &Path,
    config: &SigningConfig,
) -> Result<bool> {
    info!("Verifying signature for command");
    
    // Read signature file
    let signature_content = fs::read_to_string(signature_path)
        .with_context(|| format!("Failed to read signature file: {}", signature_path.display()))?;
    
    // Parse signature format
    let sig_parts: Vec<&str> = signature_content.trim().split('\n').collect();
    if sig_parts.len() < 2 {
        anyhow::bail!("Invalid signature format");
    }
    
    let sig_type = sig_parts[0];
    let sig_data = sig_parts[1];
    
    match sig_type {
        "SSH-SIG" => verify_ssh_signature(command, sig_data, config),
        "GPG-SIG" => verify_gpg_signature(command, sig_data, config),
        "GIT-SIG" => verify_git_signature(command, sig_data, config),
        _ => anyhow::bail!("Unknown signature type: {}", sig_type),
    }
}

fn verify_ssh_signature(
    command: &str,
    signature: &str,
    config: &SigningConfig,
) -> Result<bool> {
    debug!("Verifying SSH signature");
    
    // Create temporary files for verification
    let temp_dir = tempfile::tempdir()?;
    let message_file = temp_dir.path().join("message.txt");
    let signature_file = temp_dir.path().join("signature.sig");
    let allowed_signers_file = temp_dir.path().join("allowed_signers");
    
    // Write message to file
    fs::write(&message_file, command.as_bytes())?;
    
    // Decode and write signature
    let sig_bytes = general_purpose::STANDARD.decode(signature)
        .with_context(|| "Failed to decode base64 signature")?;
    fs::write(&signature_file, sig_bytes)?;
    
    // Create allowed_signers file from trusted keys
    create_allowed_signers_file(&allowed_signers_file, &config.trusted_keys_path)?;
    
    // Use ssh-keygen to verify signature
    let output = std::process::Command::new("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(&allowed_signers_file)
        .arg("-I")
        .arg("magicrune")
        .arg("-n")
        .arg("command")
        .arg("-s")
        .arg(&signature_file)
        .arg(&message_file)
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                info!("SSH signature verification succeeded");
                Ok(true)
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                debug!("SSH signature verification failed: {}", stderr);
                Ok(false)
            }
        }
        Err(e) => {
            debug!("ssh-keygen command failed: {}", e);
            // Fallback to manual verification if ssh-keygen is not available
            verify_ssh_signature_fallback(command, signature, config)
        }
    }
}

fn verify_gpg_signature(
    command: &str,
    signature: &str,
    config: &SigningConfig,
) -> Result<bool> {
    debug!("Verifying GPG signature");
    
    // Create temporary files for verification
    let temp_dir = tempfile::tempdir()?;
    let message_file = temp_dir.path().join("message.txt");
    let signature_file = temp_dir.path().join("signature.sig");
    
    // Write message to file
    fs::write(&message_file, command.as_bytes())?;
    
    // Decode and write signature
    let sig_bytes = general_purpose::STANDARD.decode(signature)
        .with_context(|| "Failed to decode base64 signature")?;
    fs::write(&signature_file, sig_bytes)?;
    
    // Import trusted keys to temporary keyring
    let keyring_dir = temp_dir.path().join("gnupg");
    fs::create_dir_all(&keyring_dir)?;
    
    // Set GNUPGHOME to temporary directory
    let mut cmd = std::process::Command::new("gpg");
    cmd.env("GNUPGHOME", &keyring_dir);
    
    // Import trusted keys
    if config.trusted_keys_path.exists() {
        for entry in fs::read_dir(&config.trusted_keys_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("asc") ||
               path.extension().and_then(|s| s.to_str()) == Some("gpg") {
                let import_result = std::process::Command::new("gpg")
                    .env("GNUPGHOME", &keyring_dir)
                    .arg("--import")
                    .arg(&path)
                    .output();
                
                if let Err(e) = import_result {
                    debug!("Failed to import GPG key {}: {}", path.display(), e);
                }
            }
        }
    }
    
    // Verify signature
    let output = std::process::Command::new("gpg")
        .env("GNUPGHOME", &keyring_dir)
        .arg("--verify")
        .arg(&signature_file)
        .arg(&message_file)
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                info!("GPG signature verification succeeded");
                Ok(true)
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                debug!("GPG signature verification failed: {}", stderr);
                Ok(false)
            }
        }
        Err(e) => {
            debug!("gpg command failed: {}", e);
            warn!("GPG not available for signature verification");
            Ok(false)
        }
    }
}

fn verify_git_signature(
    command: &str,
    signature: &str,
    config: &SigningConfig,
) -> Result<bool> {
    debug!("Verifying Git signature");
    
    // For now, return a placeholder
    // TODO: Implement actual Git signature verification
    Ok(false)
}

pub fn sign_artifact(
    artifact_path: &Path,
    key_path: &Path,
    algorithm: &str,
) -> Result<Vec<u8>> {
    info!("Signing artifact: {}", artifact_path.display());
    
    // Read artifact
    let artifact_data = fs::read(artifact_path)
        .with_context(|| format!("Failed to read artifact: {}", artifact_path.display()))?;
    
    // Calculate hash
    let mut hasher = Sha256::new();
    hasher.update(&artifact_data);
    let hash = hasher.finalize();
    
    match algorithm {
        "ssh-ed25519" => sign_with_ssh_ed25519(&hash, key_path),
        "gpg-rsa4096" => sign_with_gpg(&hash, key_path),
        _ => anyhow::bail!("Unsupported signing algorithm: {}", algorithm),
    }
}

fn sign_with_ssh_ed25519(hash: &[u8], key_path: &Path) -> Result<Vec<u8>> {
    // TODO: Implement SSH Ed25519 signing
    Ok(vec![])
}

fn sign_with_gpg(hash: &[u8], key_path: &Path) -> Result<Vec<u8>> {
    // TODO: Implement GPG signing
    Ok(vec![])
}

pub struct TrustedKeyStore {
    keys_dir: std::path::PathBuf,
}

impl TrustedKeyStore {
    pub fn new(keys_dir: std::path::PathBuf) -> Result<Self> {
        if !keys_dir.exists() {
            fs::create_dir_all(&keys_dir)?;
        }
        Ok(Self { keys_dir })
    }
    
    pub fn add_key(&self, key_path: &Path) -> Result<String> {
        let key_content = fs::read_to_string(key_path)?;
        
        // Extract key ID/fingerprint
        let key_id = extract_key_id(&key_content)?;
        
        // Save to trusted keys directory
        let dest_path = self.keys_dir.join(&format!("{}.pub", key_id));
        fs::copy(key_path, dest_path)?;
        
        info!("Added trusted key: {}", key_id);
        Ok(key_id)
    }
    
    pub fn list_keys(&self) -> Result<Vec<(String, String)>> {
        let mut keys = Vec::new();
        
        for entry in fs::read_dir(&self.keys_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("pub") {
                let content = fs::read_to_string(&path)?;
                let key_id = extract_key_id(&content)?;
                let key_type = detect_key_type(&content)?;
                keys.push((key_id, key_type));
            }
        }
        
        Ok(keys)
    }
    
    pub fn remove_key(&self, key_id: &str) -> Result<()> {
        let key_path = self.keys_dir.join(format!("{}.pub", key_id));
        if key_path.exists() {
            fs::remove_file(key_path)?;
            info!("Removed trusted key: {}", key_id);
        } else {
            anyhow::bail!("Key not found: {}", key_id);
        }
        Ok(())
    }
}

fn create_allowed_signers_file(file_path: &Path, trusted_keys_dir: &Path) -> Result<()> {
    let mut allowed_signers = String::new();
    
    // Read all trusted keys
    if trusted_keys_dir.exists() {
        for entry in fs::read_dir(trusted_keys_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("pub") {
                let key_content = fs::read_to_string(&path)?;
                // Format: identity keytype base64key comment
                allowed_signers.push_str(&format!("magicrune {}\n", key_content.trim()));
            }
        }
    }
    
    fs::write(file_path, allowed_signers)?;
    Ok(())
}

fn verify_ssh_signature_fallback(
    _command: &str, 
    _signature: &str, 
    _config: &SigningConfig
) -> Result<bool> {
    warn!("SSH signature verification fallback - ssh-keygen not available");
    // In production, this should implement manual SSH signature verification
    // For now, we return false (verification failed)
    Ok(false)
}

fn extract_key_id(key_content: &str) -> Result<String> {
    // Simple extraction - in reality would parse the key format
    if key_content.starts_with("ssh-") {
        // SSH key format
        let parts: Vec<&str> = key_content.split_whitespace().collect();
        if parts.len() >= 2 {
            // Use first 16 chars of the key data as ID
            Ok(parts[1].chars().take(16).collect())
        } else {
            anyhow::bail!("Invalid SSH key format");
        }
    } else if key_content.contains("BEGIN PGP") {
        // GPG key format
        Ok("gpg_placeholder_id".to_string())
    } else {
        anyhow::bail!("Unknown key format");
    }
}

fn detect_key_type(key_content: &str) -> Result<String> {
    if key_content.starts_with("ssh-rsa") {
        Ok("ssh-rsa".to_string())
    } else if key_content.starts_with("ssh-ed25519") {
        Ok("ssh-ed25519".to_string())
    } else if key_content.contains("BEGIN PGP") {
        Ok("gpg".to_string())
    } else {
        Ok("unknown".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_trusted_key_store() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = TrustedKeyStore::new(temp_dir.path().to_path_buf())?;
        
        // Create a test SSH key
        let test_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com";
        let key_file = temp_dir.path().join("test.pub");
        fs::write(&key_file, test_key)?;
        
        // Add key
        let key_id = store.add_key(&key_file)?;
        assert!(!key_id.is_empty());
        
        // List keys
        let keys = store.list_keys()?;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].1, "ssh-ed25519");
        
        // Remove key
        store.remove_key(&key_id)?;
        let keys = store.list_keys()?;
        assert_eq!(keys.len(), 0);
        
        Ok(())
    }
}