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

以上により、個人開発でも SPEC/MASTER に整合した最小コストのループで継続開発できます。

