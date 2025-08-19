# Changelog

## [0.1.0] - 2025-08-19
### Added
- CLI `magicrune exec`（schema 厳格・WASMフォールバック）
- JetStream 統合（Msg-Id dedupe / double-ack semantics）
- SBOM 生成+署名（cosign bundle）と検証
- CI（Linux/musl, Windows, macOS）+ coverage gate (>=80%)

### Security
- `cargo audit` を CI に固定（例外は .cargo/audit.toml）

