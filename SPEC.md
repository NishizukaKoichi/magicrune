# MagicRune （Rust 2021 / MSRV 1.80 固定）

## 0. Purpose

> **AI／外部生成コードを “1 回だけ” 安全に実行し、結果を返す唯一のゲート**
> 
> - 100% Linux サンドボックス（Wasm フォールバック）
>     
> - 行動ログ → AI Grading → green / yellow / red
>     
> - 結果は CLI 出力 or NATS JetStream 返信（Exactly-Once 相当の運用） ([docs.nats.io](https://docs.nats.io/using-nats/developer/develop_jetstream/model_deep_dive?utm_source=chatgpt.com "JetStream Model Deep Dive | NATS Docs"))
>     

---

## 1. 採択スタック（バージョン固定）

|Layer|Tech / Version|Pin / 根拠|
|---|---|---|
|Language / Async|**Rust 2021 + MSRV = 1.80**, **Tokio 1.47.x**|Cargo `rust-version = "1.80"` 固定。Tokio 1.47 公開（2025-07-25）。 ([blog.rust-lang.org](https://blog.rust-lang.org/2024/07/25/Rust-1.80.0/?utm_source=chatgpt.com "Announcing Rust 1.80.0 \| Rust Blog"), [GitHub](https://github.com/tokio-rs/tokio/discussions/7483?utm_source=chatgpt.com "Tokio v1.47.0 · tokio-rs tokio · Discussion #7483 · GitHub"))|
|Messaging|**NATS JetStream**（client: `async-nats` 0.39系想定・JetStream対応）|JetStream の重複排除（`Nats-Msg-Id`）と “confirmed ack / double-ack 同等” を活用。 ([docs.nats.io](https://docs.nats.io/nats-concepts/jetstream/streams?utm_source=chatgpt.com "Streams \| NATS Docs"), [natsbyexample.com](https://natsbyexample.com/examples/jetstream/ack-ack/go?utm_source=chatgpt.com "NATS by Example - Confirmed Message Ack (Go)"))|
|Sandbox（fallback）|**Wasmtime 15.x**（WASI）|15系は 2023/11～の安定系列。WASI 実行とリソース制限（ResourceLimiter / Fuel / Epoch）を利用。 ([Docs.rs](https://docs.rs/crate/wasmtime-wit-bindgen/latest?utm_source=chatgpt.com "wasmtime-wit-bindgen 15.0.1 - Docs.rs"), [docs.wasmtime.dev](https://docs.wasmtime.dev/examples-interrupting-wasm.html?utm_source=chatgpt.com "Interrupting Execution - Wasmtime"))|
|Sandbox（native）|Linux namespaces（PID/NET/MNT/USER/IPC/UTS）+ **cgroups v2** + seccomp + overlayfs(ro) + tmpfs(`/tmp`)|カーネル一次資料に基づき採用。 ([man7.org](https://www.man7.org/linux/man-pages/man7/namespaces.7.html?utm_source=chatgpt.com "namespaces (7) — Linux manual page"), [kernel.org](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html?utm_source=chatgpt.com "Control Group v2 — The Linux Kernel documentation"))|
|SBOM / Sign|**Syft**（SPDX JSON）+ **Cosign**（sign-blob：OIDC keyless）|CI で SBOM 生成と署名（id-token: write）。 ([GitHub](https://github.com/anchore/sbom-action?utm_source=chatgpt.com "GitHub - anchore/sbom-action: GitHub Action for creating software bill ..."), [Sigstore](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/?utm_source=chatgpt.com "Signing Blobs - Sigstore"))|
|CI|**GitHub Actions**（Ubuntu 24.04 固定ランナー、Artifacts v4）+ `dtolnay/rust-toolchain` + `Swatinem/rust-cache`|ランナー・アーティファクトは v4 世代を利用、速度・互換に注意。 ([GitHub](https://github.com/dtolnay/rust-toolchain?utm_source=chatgpt.com "GitHub - dtolnay/rust-toolchain: Concise GitHub Action for installing a ..."), [The GitHub Blog](https://github.blog/news-insights/product-news/get-started-with-v4-of-github-actions-artifacts/?utm_source=chatgpt.com "Get started with v4 of GitHub Actions Artifacts"))|

> 注：`async-nats` は 0.x 系で継続更新中。JetStream/ACK・KV・Object Store 等は同 crate が提供。 ([Docs.rs](https://docs.rs/crate/async-nats/latest?utm_source=chatgpt.com "async-nats 0.41.0 - Docs.rs"))

---

## 2. インタフェース

### 2.1 CLI

```bash
magicrune exec \
  -f request.json        # 必須: SpellRequest
  --policy policy.yml    # 省略時: policies/default.policy.yml
  --timeout 15           # ≤60s
  --seed 42              # 決定性 RNG
  --out result.json      # 省略時: stdout
  --strict               # schema NG で exit!=0
```

|Exit|意味|
|---|---|
|0|green|
|10|yellow|
|20|red（検疫済み）|
|1|入力スキーマ不一致|
|2|出力スキーマ不一致|
|3|ポリシー違反で未実行|
|4|内部エラー|

### 2.2 JetStream

|Subject|内容|
|---|---|
|`run.req.*`|**Msg-Id = SHA-256(request)** をヘッダ `Nats-Msg-Id` に付与（デデュープ窓内で重複無視）|
|`run.res.$RUN_ID`|SpellResult を返信（confirmed ack / double-ack 相当で確実化）|

> デデュープは header `Nats-Msg-Id` による idempotent 書き込み、ACK は「受信側からの ack をサーバが確認応答（ack-ack）」する流儀を採用。 ([docs.nats.io](https://docs.nats.io/nats-concepts/jetstream/headers?utm_source=chatgpt.com "Headers | NATS Docs"), [natsbyexample.com](https://natsbyexample.com/examples/jetstream/ack-ack/go?utm_source=chatgpt.com "NATS by Example - Confirmed Message Ack (Go)"))

---

## 3. JSON Schema（抜粋）

### 3.1 `schemas/spell_request.schema.json`

```jsonc
{
  "cmd": "bash -lc 'cargo test'",
  "stdin": "",
  "env": { "RUST_LOG": "info" },
  "files": [
    { "path": "/workspace/Cargo.toml", "content_b64": "..." }
  ],
  "policy_id": "default",
  "timeout_sec": 15,
  "allow_net": [],
  "allow_fs": []
}
```

### 3.2 `schemas/spell_result.schema.json`

```jsonc
{
  "run_id": "r_01H8C6W6PS6KD5R463JTDY7G9",
  "verdict": "green",
  "risk_score": 12,
  "exit_code": 0,
  "duration_ms": 842,
  "stdout_trunc": false,
  "sbom_attestation": "file://sbom.spdx.json.sig"
}
```

---

## 4. サンドボックス仕様

|項目|Linux (native)|Wasm (Wasmtime 15)|
|---|---|---|
|Namespaces|PID / NET / MNT / USER / IPC / UTS|—|
|FS|overlayfs 読取専用、`/tmp` は **tmpfs**|WASI で `--dir=/tmp` のみ RW|
|seccomp|allow-list（`read/write/exit/clock_*` 等）|—|
|cgroups v2|`cpu.max`, `memory.max`, `pids.max`|Store limiter / Fuel / Epoch で CPU/時間相当を制御|
|Net|既定 deny、allowlist|既定で無効|
|Time|≤ 60 s|Fuel / Epoch interrupt で制御|

> Linux の隔離機構／cgroups v2／overlayfs／tmpfs はカーネル一次資料。Wasmtime は ResourceLimiter・Fuel・Epoch により WASI 実行を**確定停止**させられる。 ([man7.org](https://www.man7.org/linux/man-pages/man7/namespaces.7.html?utm_source=chatgpt.com "namespaces (7) — Linux manual page"), [kernel.org](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html?utm_source=chatgpt.com "Control Group v2 — The Linux Kernel documentation"), [Docs.rs](https://docs.rs/wasmtime/latest/wasmtime/trait.ResourceLimiter.html?utm_source=chatgpt.com "ResourceLimiter in wasmtime - Rust - Docs.rs"), [docs.wasmtime.dev](https://docs.wasmtime.dev/examples-interrupting-wasm.html?utm_source=chatgpt.com "Interrupting Execution - Wasmtime"))

---

## 5. Policy DSL（最小）

```yaml
version: 1
capabilities:
  fs:
    default: deny
    allow:
      - path: "/tmp/**"
  net:
    default: deny
limits:
  cpu_ms: 5000
  memory_mb: 512
  wall_sec: 15
grading:
  thresholds:
    green: "<=20"
    yellow: "21..=60"
    red: ">=61"
```

---

## 6. Grading Logic

1. 静的スコア（例：未許可 NET = +40、`.ssh` 読み = +30 など）
    
2. ML 補正（RuneSage local）
    
3. `risk_score = static + ml` → verdict
    
4. verdict=red は stdout/stderr を `quarantine/` へ隔離
    

---

## 7. ディレクトリ

```
magicrune/
├─ src/
│  ├─ main.rs          # CLI & JetStream consumer
│  ├─ sandbox.rs       # linux / wasmtime 両実装
│  ├─ grader.rs
│  ├─ ledger.rs        # trait: Local(SQLite) / Remote(...)
│  └─ schema.rs
├─ policies/default.policy.yml
├─ schemas/{spell_request,spell_result}.schema.json
├─ samples/{ok.json,deny_net.json}
└─ Cargo.toml
```

---

## 8. Cargo.toml（ピン留め例）

```toml
[package]
name = "magicrune"
version = "0.1.0"
edition = "2021"
rust-version = "1.80"   # MSRV 固定（Rust 1.80 リリース根拠）  # :contentReference[oaicite:10]{index=10}

[dependencies]
tokio = { version = "1.47", features = ["rt-multi-thread","macros","process","time"] }  # :contentReference[oaicite:11]{index=11}
async-nats = { version = "0.39", features = ["jetstream"] }                               # :contentReference[oaicite:12]{index=12}
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
clap = { version = "4.5", features = ["derive"] }
base64 = "0.22"
anyhow = "1.0"
thiserror = "1.0"
# native sandbox
nix = "0.29"
# wasm fallback
wasmtime = "15"
wasmtime-wasi = "15"    # 15系が存在（2023/11～）                                           # :contentReference[oaicite:13]{index=13}
```

---

## 9. 受け入れ基準（DoD）

1. `magicrune exec -f samples/ok.json` → `result.json`（verdict=green）
    
2. 同一 request + seed → 出力ハッシュ不変
    
3. JetStream で同一 `Nats-Msg-Id` → 実行 1 回（重複無視） ([docs.nats.io](https://docs.nats.io/nats-concepts/jetstream/headers?utm_source=chatgpt.com "Headers | NATS Docs"))
    
4. verdict=red → `quarantine/` へ隔離
    
5. `cargo test --locked` で schema 検証・ユニット全通過
    

---

## 10. GitHub Actions（CI 専用・**確実に通る** 設計）

> _Linux ネイティブ沙箱（unshare/mount/cgroups）は GH ホストでは特権不足のため基本**スキップ**。CI は Wasmtime フォールバックで機能検証します。_  
> _SBOM 署名は OIDC **keyless** を使用（`permissions: id-token: write` 必須）。_ ([Sigstore](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/?utm_source=chatgpt.com "Signing Blobs - Sigstore"))

`.github/workflows/ci.yml`

```yaml
name: magicrune-ci
on:
  push:
  pull_request:

permissions:
  contents: read
  id-token: write   # cosign keyless で必要  # :contentReference[oaicite:16]{index=16}

jobs:
  test-build:
    runs-on: ubuntu-24.04   # ランナー固定
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable    # rustup で MSRV 遵守      # :contentReference[oaicite:17]{index=17}
      - uses: Swatinem/rust-cache@v2           # ビルドキャッシュ         # :contentReference[oaicite:18]{index=18}

      # Wasm フォールバックでテスト（GH 上は privilege が足りないため）
      - name: Test (wasm fallback)
        run: |
          export MAGICRUNE_FORCE_WASM=1
          cargo test --workspace --locked

      - name: Build (linux-gnu host)
        run: cargo build --release --workspace --locked

      # クロスビルド（musl 2アーキ）: cross-rs を使用
      - name: Install cross
        run: cargo install cross --git https://github.com/cross-rs/cross  # :contentReference[oaicite:19]{index=19}
      - name: Build musl (x86_64)
        run: cross build --release --target x86_64-unknown-linux-musl
      - name: Build musl (aarch64)
        run: cross build --release --target aarch64-unknown-linux-musl

      # SBOM 生成（SPDX JSON）
      - name: Generate SBOM (Syft)
        uses: anchore/sbom-action@v0   # SPDX JSON を成果物化          # :contentReference[oaicite:20]{index=20}
        with:
          output-file: sbom.spdx.json

      # 署名（keyless）
      - name: Install cosign
        uses: sigstore/cosign-installer@v3
      - name: Sign SBOM (OIDC keyless)
        run: cosign sign-blob --yes --bundle sbom.spdx.json  # bundle 形式推奨  # :contentReference[oaicite:21]{index=21}

      # アーティファクト v4
      - name: Upload artifacts
        uses: actions/upload-artifact@v4                        # v4 世代       # :contentReference[oaicite:22]{index=22}
        with:
          name: magicrune-${{ github.sha }}
          path: |
            target/x86_64-unknown-linux-musl/release/magicrune
            target/aarch64-unknown-linux-musl/release/magicrune
            sbom.spdx.json
            sbom.spdx.json.sig
```

---

## 11. Quick Start（ローカル）

```bash
# 1) リポジトリ作成
cargo new --bin magicrune && cd magicrune

# 2) Cargo.toml を上記に差し替え、schemas/policies/samples を配置

# 3) Wasmtime フォールバックで手早く動作確認
MAGICRUNE_FORCE_WASM=1 cargo test --locked

# 4) Linux ネイティブ沙箱は root 権限で（namespaces/mount/cgroups）
sudo -E env RUST_LOG=info cargo run -- exec -f samples/ok.json --timeout 10
```

---

## 12. 実装メモ（根拠）

- **JetStream**：`Nats-Msg-Id` で**重複排除**、confirmed ack（クライアント側 ack の**確認応答**）が可能。Exactly-Once 相当の運用が組める。 ([docs.nats.io](https://docs.nats.io/nats-concepts/jetstream/headers?utm_source=chatgpt.com "Headers | NATS Docs"), [natsbyexample.com](https://natsbyexample.com/examples/jetstream/ack-ack/go?utm_source=chatgpt.com "NATS by Example - Confirmed Message Ack (Go)"))
    
- **Wasmtime 15**：WASI 実行・**ResourceLimiter**、Fuel／**Epoch interruption** による実行停止が可能。 ([Docs.rs](https://docs.rs/wasmtime/latest/wasmtime/trait.ResourceLimiter.html?utm_source=chatgpt.com "ResourceLimiter in wasmtime - Rust - Docs.rs"), [docs.wasmtime.dev](https://docs.wasmtime.dev/examples-interrupting-wasm.html?utm_source=chatgpt.com "Interrupting Execution - Wasmtime"))
    
- **Linux 隔離**：namespaces／cgroups v2／overlayfs／tmpfs はカーネル文書に準拠。 ([man7.org](https://www.man7.org/linux/man-pages/man7/namespaces.7.html?utm_source=chatgpt.com "namespaces (7) — Linux manual page"), [kernel.org](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html?utm_source=chatgpt.com "Control Group v2 — The Linux Kernel documentation"))
    
- **CI**：`dtolnay/rust-toolchain`・`rust-cache` は Rust プロジェクトのデファクト。Artifacts v4 を利用。 ([GitHub](https://github.com/dtolnay/rust-toolchain?utm_source=chatgpt.com "GitHub - dtolnay/rust-toolchain: Concise GitHub Action for installing a ..."), [The GitHub Blog](https://github.blog/news-insights/product-news/get-started-with-v4-of-github-actions-artifacts/?utm_source=chatgpt.com "Get started with v4 of GitHub Actions Artifacts"))
    
- **SBOM/署名**：Syft で SPDX、Cosign の **sign-blob** はファイル署名（bundle 推奨）。 ([GitHub](https://github.com/anchore/sbom-action?utm_source=chatgpt.com "GitHub - anchore/sbom-action: GitHub Action for creating software bill ..."), [Sigstore](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/?utm_source=chatgpt.com "Signing Blobs - Sigstore"))