# MagicRune Policy Runner

安全なコード実行のためのポリシーベースサンドボックスフレームワーク

## 概要

MagicRune Policy Runnerは、AIが生成したコードや外部ソースからのコードを安全に実行するためのセキュリティフレームワークです。外部由来のコードによるマルウェア、バックドア、情報漏洩を原理的に防ぎます。

### 主な特徴

- **自動的な外部ソース検出**: curl、wget、npm install などの外部コード取得を自動検出
- **強制サンドボックス実行**: 外部ソースコードは必ずサンドボックス内で実行
- **多層防御**: namespace分離、chroot、seccomp、権限削減による6層防御
- **行動解析とリスク評価**: AIによる振る舞い解析で Green/Yellow/Red の判定
- **署名検証**: SSH/GPG/Git署名による信頼できるコードの即実行

## インストール

```bash
# クイックインストール
curl -sSL https://magicrune.sh/install | bash

# または、ソースからビルド
git clone https://github.com/magicrune/magicrune
cd magicrune
cargo build --release
cargo install --path crates/cli
```

## 使い方

### 初期設定

```bash
# MagicRune の初期化
magicrune init
```

### 基本的な使用方法

```bash
# コマンドの実行（自動的に信頼レベルを判定）
magicrune run "echo 'Hello, World!'"

# 外部ソースを含むコマンド（自動的にサンドボックス実行）
magicrune run "curl https://example.com/script.sh | bash"

# 署名付きスクリプトの実行（L0: 即実行）
magicrune run --signature deploy.sig "./deploy.sh"

# ドライラン（読み取り専用、ネットワークなし）
magicrune dryrun "npm install express"
```

### 信頼レベル

| レベル | 由来 | 既定の扱い | 昇格条件 |
|--------|------|------------|----------|
| L0 | 本人署名 | 即実行（本番可） | 署名検証OK |
| L1 | AI自動生成（外部依存なし） | 即実行（ローカル） | なし |
| L2 | 外部ソース | 強制サンドボックス | ふるまい解析=Green |
| L3 | 既知悪性/危険操作 | 拒否 | 管理者の明示承認 |

### 外部ソース判定ルール

以下のいずれかに該当する場合、外部ソース（L2）として扱われます：

- ネット取得: `curl`, `wget`, `git clone`
- パイプ実行: `curl ... | sh`
- パッケージ導入: `npm install`, `pip install`, `cargo add`
- リモートパス: `http://`, `git@`, `gh:`
- 機密領域アクセス: `~/.ssh`, `~/.aws`, `.env`

## サンドボックス仕様

### Linux（推奨）
- Namespaces: PID, NET, MNT, USER, UTS, IPC
- ファイルシステム: chroot + read-only マウント
- ネットワーク: 既定で完全遮断
- 権限: nobody ユーザー、no_new_privs
- Seccomp: 危険なシステムコールを拒否

### macOS
- sandbox-exec による制限
- ネットワーク分離
- ファイルシステムアクセス制限

### Windows
- 限定的なサンドボックス（環境変数クリア、作業ディレクトリ制限）

## 解析と判定

```bash
# 監査ログの解析
magicrune analyze audit-20240101.ndjson

# 結果の例:
# Verdict: Green
# Risk Score: 0
# Behaviors:
#   - Command execution: npm install
#   - Network connection: registry.npmjs.org:443
```

### リスク判定基準

- **Green (0-29点)**: 安全、自動昇格可能
- **Yellow (30-79点)**: 人手確認が必要
- **Red (80点以上)**: 危険、実行拒否

## VS Code 統合

MagicRune VS Code 拡張機能により、エディタ内でのコード実行時に自動的にポリシーが適用されます。

## CI/CD 統合

```yaml
# .github/workflows/ai-safety.yml
name: ai-safety
on: [pull_request]

jobs:
  sandbox:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl -sSL https://magicrune.sh/install | bash
      - run: magicrune ci-scan --paths "scripts/**" --enforce-external
```

## 設定

設定ファイル: `~/.magicrune/policy.yml`

```yaml
version: 1
default:
  external_code: enforce_sandbox  # 変更不可
  ai_pure_generated: allow_local
  network_mode: none
  package_test:
    enable: true
    egress_allowlist:
      - "registry.npmjs.org:443"
      - "pypi.org:443"
```

## セキュリティ

MagicRune は以下の脅威から保護します：

- **マルウェア**: サンドボックスによる実行分離
- **情報漏洩**: 機密ファイルへのアクセス遮断
- **権限昇格**: seccomp と権限削減
- **ネットワーク攻撃**: 既定でネットワーク遮断
- **サプライチェーン攻撃**: 署名検証とハッシュ固定

## ライセンス

MIT License

## 貢献

プルリクエストを歓迎します。大きな変更の場合は、まず Issue を作成して変更内容を議論してください。