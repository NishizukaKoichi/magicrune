#[cfg(not(target_env = "musl"))]
mod jet_tests {
    use std::net::TcpStream;

    #[test]
    fn nats_tcp_port_open() {
        let addr = std::env::var("NATS_TCP").unwrap_or_else(|_| "127.0.0.1:4222".to_string());
        let s = TcpStream::connect(&addr).expect("connect tcp 4222");
        let _ = s;
    }
}
