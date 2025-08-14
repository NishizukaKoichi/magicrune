# Build stage
FROM rust:1.88-slim AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build release binary
RUN cargo build --release --locked

# Runtime stage - use debian slim (not alpine/musl)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/bootstrapped /usr/local/bin/bootstrapped

ENTRYPOINT ["/usr/local/bin/bootstrapped"]