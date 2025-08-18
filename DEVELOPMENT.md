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

MSRV=1.80 固定で `--features jet` を利用する場合、依存解決が rustc 1.81+ を要求する可能性があります。その場合の回避策:

- 一時的に Rust 1.82 へ切替（推奨）: `rustup override set 1.82.0`（検証後 `rustup override unset`）
- もしくは依存を MSRV 1.80 互換へピン止め（要ネット）:
  - `cargo update -p url --precise 2.4.1`
  - `cargo update -p ed25519-dalek --precise 2.1.1`

どちらの方法でも `cargo build --features jet` が通ればスモーク可能です。

#### 運用チューニング用の環境変数

- `NATS_URL` / `NATS_REQ_SUBJ` / `NATS_STREAM` / `NATS_DURABLE`
- `NATS_MAX_ACK_PENDING`（既定: 2048）
- `NATS_ACK_WAIT_SEC`（既定: 30）
- `MAGICRUNE_POLICY`（既定: `policies/default.policy.yml`）

メトリクスは標準エラーに100件ごとに集計を出力（processed/dupes/reds）。

以上により、個人開発でも SPEC/MASTER に整合した最小コストのループで継続開発できます。
