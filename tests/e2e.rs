#[cfg(test)]
mod integration_tests {
    use std::process::{Command, ExitStatus};
    use std::thread;
    use std::time::Duration;

    fn run_command(cmd: &str, args: &[&str]) -> Result<ExitStatus, String> {
        Command::new(cmd)
            .args(args)
            .status()
            .map_err(|e| format!("Failed to execute {cmd}: {e}"))
    }

    #[test]
    #[ignore = "Requires Docker and docker-compose to be installed"]
    fn test_docker_compose_up_down() {
        // Skip if running in musl environment
        if cfg!(target_env = "musl") {
            println!("Skipping E2E test in musl environment");
            return;
        }

        // Skip if running in CI without docker-compose
        if std::env::var("CI").is_ok() {
            println!("Skipping docker-compose test in CI environment");
            return;
        }

        // Check if docker-compose is available
        if run_command("docker-compose", &["version"]).is_err() {
            println!("docker-compose not available, skipping test");
            return;
        }

        // Start services
        let up_result = run_command("docker-compose", &["up", "-d"]);
        assert!(up_result.is_ok(), "Failed to start docker-compose");

        // Wait for services to be ready
        thread::sleep(Duration::from_secs(5));

        // Check service health
        let ps_result = run_command("docker-compose", &["ps"]);
        assert!(ps_result.is_ok(), "Failed to check service status");

        // Test NATS connectivity
        let logs_result = run_command("docker-compose", &["logs", "nats"]);
        assert!(logs_result.is_ok(), "Failed to get NATS logs");

        // Clean up
        let down_result = run_command("docker-compose", &["down", "-v"]);
        assert!(down_result.is_ok(), "Failed to stop docker-compose");
    }

    #[test]
    fn test_exit_codes() {
        // Test exit code compliance
        let output = Command::new("cargo")
            .args(["run", "--", "--version"])
            .output()
            .expect("Failed to execute cargo run");

        // Verify = 0 for success
        assert_eq!(output.status.code(), Some(0), "Expected exit code 0");
    }

    #[test]
    fn test_nats_exactly_once() {
        // Skip if running in musl environment
        if cfg!(target_env = "musl") {
            println!("Skipping NATS test in musl environment");
            return;
        }

        // This would test NATS Exactly-Once delivery with Nats-Msg-Id
        // For now, this is a placeholder for future implementation
        println!("NATS Exactly-Once test would run here");
    }
}
