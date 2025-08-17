#[cfg(not(target_env = "musl"))]
mod jet_tests {
    use std::net::TcpStream;

    #[test]
    fn nats_tcp_port_open() {
        // Only enforce when explicitly requested; otherwise, skip gracefully
        // to keep tests deterministic and free of external dependencies.
        let require = std::env::var("MAGICRUNE_REQUIRE_NATS").ok() == Some("1".to_string());
        let addr = std::env::var("NATS_TCP").unwrap_or_else(|_| "127.0.0.1:4222".to_string());
        match TcpStream::connect(&addr) {
            Ok(_s) => {
                // Connected; pass
            }
            Err(e) => {
                if require {
                    panic!("failed to connect to {}: {}", addr, e);
                } else {
                    eprintln!(
                        "NATS not reachable at {} ({}); skipping smoke test",
                        addr, e
                    );
                }
            }
        }
    }
}
