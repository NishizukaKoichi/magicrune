# MagicRune

MagicRune is a bootstrapped Rust/WASM edge runner that executes untrusted spells once in a sandbox, grades the behavior, and reports results via CLI or NATS JetStream.

- MSRV: Rust 1.82, Edition 2021
- Sandboxes: Linux native (namespaces + RLIMIT + optional seccomp/cgroups/overlayfs(ro)), WASI fallback (Wasmtime 15, fuel/epoch/ResourceLimiter)
- Messaging: NATS JetStream (dedupe via Nats-Msg-Id, durable pull consumer, ack-ack style)

Quick start:

```
cargo run --bin magicrune -- exec -f samples/ok.json --strict
```

JetStream (local):

```
docker compose up -d nats
cargo run --features jet --bin magicrune -- consume &
cargo run --features jet --bin js_publish -- samples/ok.json
```

See DEVELOPMENT.md for details on CI, security scanning (Gitleaks), SBOM signing, sandboxes, and E2E scenarios.
