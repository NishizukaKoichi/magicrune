# **MagicRune （Rust 2021 / MSRV 1.82 固定）**

  

## **0. Purpose**

  

> **AI／外部生成コードを “1 回だけ” 安全に実行し、結果を返す唯一のゲート**

- > 100% Linux サンドボックス（Wasm フォールバック）
    
- > 行動ログ → AI Grading → green / yellow / red
    
- > 結果は CLI 出力 or NATS JetStream 返信（Exactly-Once 相当の運用）
    

---

## **1. 採択スタック（バージョン固定）**

|**Layer**|**Tech / Version**|**Pin / 根拠**|
|---|---|---|
|Language / Async|**Rust 2021 + MSRV = 1.82**, **Tokio 1.47.x**|Cargo の rust-version = "1.82" に固定（依存の要件満たすため）。Tokio は 1.47 系を固定。|
|Messaging|**NATS JetStream**（client: async-nats 0.39系想定・JetStream対応）|JetStream のデデュープ（Nats-Msg-Id）と confirmed ack / double-ack 同等を活用。|
|Sandbox（fallback）|**Wasmtime 15.x**（WASI）|WASI 実行とリソース制限（ResourceLimiter / Fuel / Epoch）を利用。|
|Sandbox（native）|Linux namespaces（PID/NET/MNT/USER/IPC/UTS）+ **cgroups v2** + seccomp + overlayfs(ro) + tmpfs(/tmp)|カーネル一次資料に基づく。|
|SBOM / Sign|**Syft**（SPDX JSON）+ **Cosign**（sign-blob：OIDC keyless）|CI で SBOM 生成と署名（id-token: write）。|
|CI|**GitHub Actions**（Ubuntu 24.04 固定ランナー、Artifacts v4）+ dtolnay/rust-toolchain + Swatinem/rust-cache|rust-toolchain を 1.82 に固定。|

> 注：async-nats は 0.x 系で継続更新。JetStream/ACK・KV・Object Store などは同 crate が提供。

---

## **2. インタフェース**

  

### **2.1 CLI**

```
magicrune exec \
  -f request.json        # 必須: SpellRequest
  --policy policy.yml    # 省略時: policies/default.policy.yml
  --timeout 15           # ≤60s
  --seed 42              # 決定性 RNG
  --out result.json      # 省略時: stdout
  --strict               # schema NG で exit!=0
```

|**Exit**|**意味**|
|---|---|
|0|green|
|10|yellow|
|20|red（検疫済み）|
|1|入力スキーマ不一致|
|2|出力スキーマ不一致|
|3|ポリシー違反で未実行|
|4|内部エラー|

### **2.2 JetStream**

|**Subject**|**内容**|
|---|---|
|run.req.*|**Msg-Id = SHA-256(request)** をヘッダ Nats-Msg-Id に付与（デデュープ窓内で重複無視）|
|run.res.$RUN_ID|SpellResult を返信（confirmed ack / double-ack 相当で確実化）|

---

## **3. JSON Schema（抜粋）**

  

### **3.1** 

### **schemas/spell_request.schema.json**

```
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

### **3.2** 

### **schemas/spell_result.schema.json**

```
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

## **4. サンドボックス仕様**

|**項目**|**Linux (native)**|**Wasm (Wasmtime 15)**|
|---|---|---|
|Namespaces|PID / NET / MNT / USER / IPC / UTS|—|
|FS|overlayfs 読取専用、/tmp は **tmpfs**|WASI で --dir=/tmp のみ RW|
|seccomp|allow-list（read/write/exit/clock_* 等）|—|
|cgroups v2|cpu.max, memory.max, pids.max|Store limiter / Fuel / Epoch|
|Net|既定 deny、allowlist|既定で無効|
|Time|≤ 60 s|Fuel / Epoch interrupt|

---

## **5. Policy DSL（最小）**

```
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

## **6. Grading Logic**

1. 静的スコア（例：未許可 NET = +40、.ssh 読み = +30 など）
    
2. ML 補正（RuneSage local）
    
3. risk_score = static + ml → verdict
    
4. verdict=red は stdout/stderr を quarantine/ へ隔離
    

---

## **7. ディレクトリ**

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

## **8. Cargo.toml（ピン留め例）**

```
[package]
name = "magicrune"
version = "0.1.0"
edition = "2021"
rust-version = "1.82"   # MSRV 固定

[dependencies]
tokio = { version = "1.47", features = ["rt-multi-thread","macros","process","time"] }
async-nats = { version = "0.39", features = ["jetstream"] }
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
wasmtime-wasi = "15"
```

---

## **9. 受け入れ基準（DoD）**

1. magicrune exec -f samples/ok.json → result.json（verdict=green）
    
2. 同一 request + seed → 出力ハッシュ不変
    
3. JetStream で同一 Nats-Msg-Id → 実行 1 回（重複無視）
    
4. verdict=red → quarantine/ へ隔離
    
5. cargo test --locked で schema 検証・ユニット全通過
    

---

## **10. GitHub Actions（CI 専用・**

## **確実に通る**

##  **設計）**

  

> _Linux ネイティブ沙箱（unshare/mount/cgroups）は GH ホストでは特権不足のため基本スキップ。CI は Wasmtime フォールバックで機能検証。_

> _SBOM 署名は OIDC_ **_keyless_** _を使用（__permissions: id-token: write_ _必須）。_

  

.github/workflows/ci.yml

```
name: magicrune-ci
on:
  push:
  pull_request:

permissions:
  contents: read
  id-token: write

jobs:
  test-build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Set up Rust toolchain (MSRV)
        uses: dtolnay/rust-toolchain@v1
        with:
          toolchain: 1.82.0
          override: true

      - uses: Swatinem/rust-cache@v2

      - name: Test (wasm fallback)
        run: |
          export MAGICRUNE_FORCE_WASM=1
          cargo test --workspace --locked

      - name: Build (linux-gnu host)
        run: cargo build --release --workspace --locked

      - name: Install cross
        run: cargo install cross --git https://github.com/cross-rs/cross
      - name: Build musl (x86_64)
        run: cross build --release --target x86_64-unknown-linux-musl
      - name: Build musl (aarch64)
        run: cross build --release --target aarch64-unknown-linux-musl

      - name: Generate SBOM (Syft)
        uses: anchore/sbom-action@v0
        with:
          output-file: sbom.spdx.json

      - name: Install cosign
        uses: sigstore/cosign-installer@v3
      - name: Sign SBOM (OIDC keyless)
        run: cosign sign-blob --yes --bundle sbom.spdx.json

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: magicrune-${{ github.sha }}
          path: |
            target/x86_64-unknown-linux-musl/release/magicrune
            target/aarch64-unknown-linux-musl/release/magicrune
            sbom.spdx.json
            sbom.spdx.json.sig
```

---

## **11. 性能基準（Performance Baseline）**

### **11.1 レイテンシ目標**
- **P50**: ≤ 50ms (単純なecho/計算タスク)
- **P95**: ≤ 200ms (ファイル操作を含むタスク)
- **P99**: ≤ 500ms (ネットワークアクセスを含むタスク)

### **11.2 スループット目標**
- **最小**: 100 req/s (シングルインスタンス)
- **推奨**: 500 req/s (4コア環境)

### **11.3 リソース制限**
- **メモリ上限**: 128MB/リクエスト（デフォルト）
- **CPU時間**: 5秒/リクエスト（デフォルト）
- **Wall時間**: 15秒/リクエスト（デフォルト）
- **プロセス数**: 10プロセス/リクエスト

### **11.4 ベンチマーク実行**
```bash
# ベンチマーク実行
cargo bench

# 特定のベンチマークのみ
cargo bench compute_msg_id
cargo bench grade
cargo bench sandbox
```

---

## **12. Quick Start（ローカル）**

```
# 1) リポジトリ作成
cargo new --bin magicrune && cd magicrune

# 2) Cargo.toml を上記に差し替え、schemas/policies/samples を配置

# 3) Wasmtime フォールバックで手早く動作確認
MAGICRUNE_FORCE_WASM=1 cargo test --locked

# 4) Linux ネイティブ沙箱は root 権限で（namespaces/mount/cgroups）
sudo -E env RUST_LOG=info cargo run -- exec -f samples/ok.json --timeout 10
```

---

## **12. 実装メモ（根拠）**

- **JetStream**：Nats-Msg-Id による重複排除、confirmed ack（クライアント ack の確認応答）で Exactly-Once 相当の運用。
    
- **Wasmtime 15**：WASI 実行・ResourceLimiter／Fuel／Epoch interruption により確定停止が可能。
    
- **Linux 隔離**：namespaces／cgroups v2／overlayfs／tmpfs はカーネル文書どおり。
    
- **CI**：dtolnay/rust-toolchain／rust-cache／Artifacts v4 を使用。
    
- **SBOM/署名**：Syft（SPDX）＋ Cosign（sign-blob, OIDC keyless）。
