# GitHubへの公開手順

## 1. GitHubリポジトリの作成

1. [GitHub](https://github.com)にログイン
2. 右上の「+」→「New repository」
3. Repository name: `magicrune`
4. Description: `Policy-based sandbox framework for safe execution of AI-generated and external code`
5. Public repository を選択
6. **Do NOT** initialize with README（既にあるため）
7. Create repository

## 2. リモートリポジトリの設定

```bash
cd "/Users/koichinishizuka/MagicRune Policy Runner/magicrune"

# GitHubのユーザー名を YOUR_USERNAME に置き換えて実行
git remote add origin https://github.com/YOUR_USERNAME/magicrune.git

# プッシュ
git branch -M main
git push -u origin main
```

## 3. GitHub Releasesの作成

1. GitHubのリポジトリページで「Releases」をクリック
2. 「Create a new release」
3. Tag version: `v0.1.0`
4. Release title: `MagicRune v0.1.0 - Initial Release`
5. 説明文を記入
6. `release.sh`で生成した`dist/*.tar.gz`ファイルをアップロード
7. 「Publish release」

## 4. crates.io への公開（オプション）

```bash
# crates.ioアカウントでログイン
cargo login

# 依存関係の順に公開
cargo publish -p magicrune-audit
cargo publish -p magicrune-policy
cargo publish -p magicrune-detector
cargo publish -p magicrune-analyzer
cargo publish -p magicrune-sign
cargo publish -p magicrune-runner
cargo publish -p magicrune
```

## 5. Homebrew Tapの作成（macOS配布用）

```bash
# homebrew-magicrune リポジトリを作成
# https://github.com/YOUR_USERNAME/homebrew-magicrune

# Formula をコピー
cp homebrew-formula.rb Formula/magicrune.rb

# SHA256を更新
shasum -a 256 dist/*.tar.gz
# 結果をhomebrew-formula.rbに反映
```

## 6. インストール方法の更新

READMEとinstall.shのURLを実際のGitHubユーザー名に更新：

```bash
# YOUR_USERNAME を実際のユーザー名に置き換え
sed -i '' 's/YOUR_USERNAME/実際のユーザー名/g' README.md
sed -i '' 's/YOUR_USERNAME/実際のユーザー名/g' install.sh
sed -i '' 's/YOUR_USERNAME/実際のユーザー名/g' homebrew-formula.rb
```

## 7. 公開後の確認

- [ ] GitHubページが正しく表示される
- [ ] READMEが読みやすい
- [ ] Issuesが有効
- [ ] GitHub Actionsが動作する
- [ ] ライセンスが表示される

## 完了！

これでMagicRuneが世界中の開発者に使ってもらえるようになります。