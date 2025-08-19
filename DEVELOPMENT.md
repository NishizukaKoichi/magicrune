# DEVELOPMENT.md — ローカル実装フロー（個人開発）

本プロジェクトは `MASTER.md` と `SPEC.md` を唯一の参照元として実装します。個人開発を前提に、ローカルでの実装と検証を完了させたうえで `main` に直接 push します（PR は任意、CI は次工程での安全弁）。

## 前提条件

- リポジトリはブーストラップ済みで、`Cargo.toml` / `src` / `tests` / `schemas` / `policies` / `samples` が揃っています。
- 変更は WORKDIR（このリポジトリ）配下に限定し、差分は最小限とします。
- 公開 API の破壊的変更（breaking change）は禁止。新規ツール導入も禁止（SPEC に明記されている場合のみ許可）。
- secrets / force-push / 履歴改変 / 浮動タグは禁止。

## 開発フロー（Local Only）

1) クローン → 仕様読込  
   - `MASTER.md` / `SPEC.md` を全文確認。

2) 実装着手（モジュール or CLI 単位）  
   - 受入テスト（`tests/`）を先に追加し、最小実装で満たす。
   - 決定的出力を優先、外部依存を避ける。WASI フォールバック優先。

3) ローカル緑 = 実装完了（DoD）  
   - `cargo fmt --all` で整形。
   - `cargo test --locked` が全て通過。
   - `cargo clippy -D warnings`（環境により未導入の場合は次工程の CI で担保）。
   - 上記が緑になったらローカルでコミット。

4) GitHub 反映（次工程）  
   - 個人開発のため `main` に直接 push。CI は安全弁として動作（Wasmtime フォールバック）。
   - CI エラー時はログ先頭 20–30 行を確認→ローカル再現→最小修正→再 push。

## 実装メモ

- CLI `magicrune exec` は SPEC に準拠した最小インタフェースを提供し、`samples/ok.json` 実行で `verdict=green` を返します。
- `tests/acceptance.rs` で受入を自動化。NATS は外部依存のため、`tests/nats_smoke.rs` は未起動環境ではスキップ（`MAGICRUNE_REQUIRE_NATS=1` で厳格化可能）。
- サンドボックス選択は既定で WASI。`linux_native` フィーチャ＋Linux ではネイティブ（ただし CI/ローカルの権限に応じてフォールバック）。

### JetStream スモーク（ローカル）

ネットワークとNATSが利用可能な環境で以下を実行:

1) コンシューマ起動（別ターミナル推奨）
   - `cargo run --features jet --bin js_consumer`
   - `NATS_URL` 既定: `127.0.0.1:4222`、`NATS_REQ_SUBJ` 既定: `run.req.default`

2) パブリッシャでリクエスト送信＋返信受信
   - `cargo run --features jet --bin js_publish -- samples/ok.json`

MSRV は Rust 1.82 固定です。`--features jet` でも追加の回避策は不要です。

#### 運用チューニング用の環境変数

- `NATS_URL` / `NATS_REQ_SUBJ` / `NATS_STREAM` / `NATS_DURABLE`
- `NATS_MAX_ACK_PENDING`（既定: 2048）
- `NATS_ACK_WAIT_SEC`（既定: 30）
- `MAGICRUNE_POLICY`（既定: `policies/default.policy.yml`）

メトリクスは標準エラーに100件ごとに集計を出力（processed/dupes/reds）。

### CI 二段構成（MSRVとcross）

- `msrv-check` ジョブ: Rust 1.82.0 で `cargo test --locked` / `cargo build --locked`
- `cross-build` ジョブ: nightly に切替後 `cargo install cross` → musl 2ターゲット build
- 成果物: musl バイナリ2種, SBOM (`sbom.spdx.json`), 署名 (`sbom.spdx.json.sig`), `dist/checksums.txt`

検証コマンド（SBOM署名）:

```
cosign verify-blob --output-signature sbom.spdx.json.sig sbom.spdx.json
```

### 環境変数一覧（抜粋）

- NATS_URL, NATS_REQ_SUBJ, NATS_STREAM, NATS_DURABLE
- NATS_MAX_ACK_PENDING, NATS_ACK_WAIT_SEC, NATS_DUP_WINDOW_SEC
- MAGICRUNE_POLICY, MAGICRUNE_DEDUPE_MAX, MAGICRUNE_METRICS_EVERY, ACK_ACK_WAIT_SEC

### Gitleaks（最小Allowlist / blocking）

- `.gitleaks.toml` は samples/, policies/*.yml, NATS localhost 既定のみを除外
- CI は `--redact --config .gitleaks.toml`（必要に応じ `--no-git`）で実行、blocking 継続

以上により、個人開発でも SPEC/MASTER に整合した最小コストのループで継続開発できます。
### E2E（Exactly-Once）— 実運用拡張

前提: `docker compose up -d nats` で NATS を起動し、ローカル `NATS_URL` を設定。

例:
```
docker compose up -d nats
export NATS_URL=nats://127.0.0.1:4222
export NATS_STREAM=RUN
export NATS_DURABLE=RUN_WORKER
export NATS_DUP_WINDOW_SEC=120
export NATS_ACK_WAIT_SEC=5
export MAGICRUNE_TEST_DELAY_MS=200
export MAGICRUNE_TEST_DELAY_MS_JITTER=200..=800
cargo test -- --nocapture jet_e2e
```

観測ポイント:
- 重複 publish は dedupe により 2 回目がタイムアウト（返信なし）
- `MAGICRUNE_TEST_SKIP_ACK_ONCE=1` + `NATS_ACK_WAIT_SEC` 短縮で再配信を誘発、Consumer 側の metrics が更新
- NET/FS ポリシー違反は即応答（red/violation）し、重複 publish を行っても 2 回目は dedupe でタイムアウト

テスト用 ENV（抜粋）
- `JS_PUBLISH_TIMEOUT_SEC`: publisher 側の返信待ちタイムアウト秒
- `MAGICRUNE_TEST_DELAY_MS`: Consumer 応答前の固定遅延（ms）
- `MAGICRUNE_TEST_DELAY_MS_JITTER`: 乱数遅延（ms）例 `200..=800`（固定遅延に加算）
- `MAGICRUNE_TEST_SKIP_ACK_ONCE`: `1` で最初の処理のみ ack をスキップ（再配信誘発）
- `MAGICRUNE_METRICS_FILE`: Consumer 側で `total/dupe/red` を JSON で書き出し
- `MAGICRUNE_METRICS_TEXTFILE`: Prometheus textfile 互換（例 `/tmp/magicrune.prom`）に簡易カウンタを書き出し
### ネイティブサンドボックス（最小 / 縮退安全）

- 機能: `linux_native` + `native_sandbox`（ビルド時）、`MAGICRUNE_SECCOMP=1`（実行時）
- 内容: seccomp で最小許可（read/write/exit/futex/clock_*/rt_sig*/poll/openat/statx/close/mmap/munmap 等）
- 失敗時: WARN を出して自動縮退（実行は継続）
- /tmp 制限: 子プロセスは `/tmp` を CWD/TMPDIR として実行（強制ではないが安全側）
- overlayfs(ro): `MAGICRUNE_OVERLAY_RO=1` で試行（NEWNS+overlay+ro / +tmpfs:/tmp）。非対応環境では WARN を出し縮退。

例（Linux/特権環境推奨）:

```
cargo build --features native_sandbox --locked
MAGICRUNE_OVERLAY_RO=1 cargo run --bin magicrune -- exec -f samples/ok.json --strict
```

注意: GitHub Hosted Runner 等では非特権 overlayfs が無効な場合があり、`[overlay-ro] WARN: enable failed, fallback: ...` と縮退します。

### seccomp（最小→緩和）

- 最小許可は echo 程度のシェル実行に必要な syscall のみ。
- `MAGICRUNE_SECCOMP_LOOSEN=1` で `getrandom, prlimit64, setrlimit, clone3` を追許可。
- 失敗は `WARN [seccomp] enable failed, fallback`。

### NET allowlist（CIDR/IPv6/範囲ポート）

- 許可例: `127.0.0.0/8`, `2001:db8::/32`, `*.example.com:443`, `127.0.0.1:8080-8090`, `[::1]`。
- 注意: IPv6 URL は `http://[::1]/` のように角括弧でホスト部を括る必要あり。
