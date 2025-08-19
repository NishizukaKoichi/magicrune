# Security Policy

This project treats secrets and sandboxing seriously.

- MSRV: 1.82, Edition 2021
- Gitleaks: Blocking with a minimal allowlist (samples/, policies/*.yml, NATS localhost)
- SBOM: Generated via Syft, signed with cosign (OIDC keyless), verified in CI

Secret handling
- Never commit secrets. If a secret leaks: revoke/rotate immediately, purge from history, and switch to env/CI secrets.
- Gitleaks runs on every PR/push; false positives are tightly scoped.

Sandboxing
- WASI fallback (Wasmtime 15): fuel/epoch/ResourceLimiter
- Linux native: namespaces + RLIMIT + optional seccomp/cgroups/overlayfs(ro); failure logs WARN and falls back safely

Reporting
- Please open an issue or contact maintainers for vulnerabilities. Provide minimal reproduction when possible.
