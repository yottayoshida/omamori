# 実装プラン: omamori — AI Agent 専用の危険コマンドセーフガード

## 概要

AI CLIツール（Claude Code, Codex, Cursor等）経由でコマンドが実行される時のみ、危険コマンドを安全な代替動作に置き換えるOSSツール。ターミナル直叩きでは無効。環境変数ゲート付きPATH shim + Claude Code Hooks のハイブリッド方式で実現する。

## 非機能要件（合意済み）

| 項目 | 要件 | 優先度 |
|------|------|--------|
| 性能 | shim のオーバーヘッド < 10ms（非AI環境では最短パスで素通し） | 高 |
| セキュリティ | shim 自体が攻撃面にならない。構造的限界を SECURITY.md で正直に開示 | 高 |
| 可用性 | shim クラッシュ時は fail-open、設定破損時は fail-close（デフォルトルールで保護維持） | 高 |
| 保守性 | TOML 設定ファイルでルール追加可能。コード変更不要で拡張 | 高 |
| コスト | 外部サービス依存なし。ローカル完結 | 中 |

## 技術選定

| 技術/ライブラリ | 選定理由 | 代替案 |
|---------------|---------|--------|
| **Rust** | 起動速度 < 1ms、メモリ安全性、cargo/brew 配布。yotta 環境に cargo 既存 | Go（起動 5ms）、Shell（複雑なパターンマッチに限界） |
| **TOML** 設定 | Rust エコシステムと親和性高。serde + toml crate で型安全パース | YAML（Rust での扱いがやや煩雑） |
| **trash crate** | macOS ゴミ箱 API のラッパー。独自実装不要 | trash-cli（Node.js、起動コスト大） |
| **env var gate** | `CLAUDECODE=1` が公式存在。テスト容易性最高（QA 評価） | ppid 追跡（OS依存、再現性低） |

## 設計方針

### アーキテクチャ: Detector Providers + PATH shim + Hooks ハイブリッド

```
[AI CLIツール] ---(env var)--> [Detector Provider] ---(AI経由と判定)--> [ルールマッチ] --> [代替動作]
                                      |
                                 (どのProviderもマッチしない)
                                      |
                                 [素通し → /usr/bin/rm]

[Claude Code] ---(PreToolUse Hook)--> [第2防御層: /bin/rm 直指定を検知]
```

**Detector Provider アーキテクチャ**（Codex②指摘で追加）:
各AIツールの検知ロジックを Provider として抽象化。共通の `DetectorProvider` trait を実装する。

```toml
# 設定ファイルの [[detectors]] がそのまま providers に対応
[[detectors]]
name = "claude-code"
type = "env_var"
env_key = "CLAUDECODE"
env_value = "1"

[[detectors]]
name = "codex-cli"
type = "env_var"
env_key = "AI_GUARD"    # Codex の shell_environment_policy.set で注入
env_value = "1"

[[detectors]]
name = "cursor"          # 暫定。公式マーカー提供まで手動設定
type = "env_var"
env_key = "AI_GUARD"
env_value = "1"
```

**第1層（PATH shim + Detector Providers）**: いずれかの Provider がマッチした時のみ発動。
**第2層（Hooks）**: Claude Code 専用。フルパス指定（`/bin/rm`）や `unset CLAUDECODE` の回避策を検知。

### nanika との関係

- **nanika**: 検知 → 翻訳（ユーザーへの説明）。PreToolUse Hook として動作
- **omamori**: 検知 → 置換（代替動作の実行）。PATH shim として動作
- **補完関係**: nanika が「何が起きようとしているか説明」→ omamori が「安全な代替に置き換え」

### 代替動作の種類（v0.1）

| action | 動作 | 対象コマンド例 |
|--------|------|--------------|
| `trash` | ゴミ箱移動（macOS Trash API） | rm -rf |
| `stash-then-exec` | git stash 後に元コマンド実行 | git reset --hard |
| `block` | 実行拒否 + エラーメッセージ | chmod 777, git push --force |
| `log-only` | ログ記録のみ、実行は許可 | 監査用途 |

※ `confirm`（インタラクティブプロンプト）は v0.1 では除外（非TTY環境で詰まるリスク）
※ `rewrite`（引数書き換え）は v0.1 では除外（コマンドインジェクションリスク、Codex指摘）

### fail-open / fail-close ポリシー（状態遷移マトリクス）

Codex②指摘: 境界が曖昧だったため、全状態を明示的に定義。

| 障害ドメイン | ポリシー | 具体的な挙動 | 理由 |
|-------------|---------|------------|------|
| shim バイナリ自体のクラッシュ | **fail-open** | 元コマンドをそのまま exec | ユーザーの作業が止まらない |
| 設定ファイルのパース失敗 | **fail-close** | 組み込みデフォルトルールで保護継続 + stderr に警告 | 破損設定で保護が消えるのを防ぐ |
| 設定ファイルの未存在 | **fail-close** | 組み込みデフォルトルール（rm -rf, git reset --hard, git push --force, chmod 777 を block）で動作 | ゼロコンフィグでも最低限の保護 |
| trash 操作の失敗 | **fail-close** | 元の rm を実行せず、exit 1 + エラーメッセージ | trash 失敗で rm が走ると意図と逆 |
| detector 判定エラー | **fail-close** | 保護を発動させる（偽陰性より偽陽性を選ぶ） | 安全側に倒す |
| sudo 実行を検出 | **block** | 実行拒否 + 警告ログ（引数は伏せ字） | sudo で保護が消えるのは危険（Codex②指摘） |

### オーケストレーターの判断記録

**何を決めたか:**
- 環境変数ゲート + Hooks のハイブリッド型を採用
- Rust で実装、TOML 設定
- MVP は Claude Code + rm/git のみ

**なぜ決めたか:**
- CLAUDECODE=1 が公式に存在し、テスト容易性が最高（QA評価）
- Hooks 単体では Codex/Cursor に対応できない（Architect指摘）
- PATH shim 単体では /bin/rm 直指定を防げない（全員一致の事実）
- ハイブリッドで両方の弱点を補完する

**何を捨てたか:**
- kernel-level フック → 複雑すぎる（nono 方式は v1+ で検討）
- Windows / Linux 対応 → macOS ファースト
- confirm / rewrite アクション → 非TTY問題 + インジェクションリスク
- SLSA / コード署名 → OSS 公開時に対応（v0.1 は yotta 環境テスト）
- 独自 trash 実装 → trash crate に委譲

## 実装ステップ（概要レベル）

Codex②指摘: ルール/テスト基盤を先に固め、配備連携は後段に。

### /develop Round 1: コア実装（ルール/テスト先行）

コアロジックを全て実装し、`omamori test` でルール検証できる状態にする。

1. [x] プロジェクトセットアップ（cargo init, CI）
2. [ ] 設定ファイル定義（TOML スキーマ + デフォルトルール組み込み） → `src/config.rs`
3. [ ] Detector Providers 実装（claude-code, codex, cursor 暫定） → `src/detector.rs`
4. [ ] ルールエンジン（コマンド + パターン → アクション判定） → `src/rules.rs`
5. [ ] **ポリシーテスト基盤**（`omamori test` — ルールが意図通り発火するか検証）
6. [ ] 代替動作の実装（trash, stash-then-exec, block, log-only） → `src/actions/`
7. [ ] 監査ログ（privacy-preserving audit schema） → `src/audit.rs`
8. [ ] ユニットテスト + 結合テスト

**Round 1 完了条件**: `cargo test` 全パス + `omamori test` でデフォルトルールの発火検証が動く

### /develop Round 2: 配備・ドキュメント・統合テスト

PATH shim の配置、Hooks 連携、ドキュメントを整備し、yotta 環境で実運用テスト。

9. [ ] PATH shim バイナリの生成・配置（`omamori install`） → `src/installer.rs`
10. [ ] Claude Code Hooks 連携（PreToolUse Hook スクリプト生成）
11. [ ] ドキュメント（README, SECURITY.md — 保護対象/非対象コマンド一覧）
12. [ ] yotta 環境での統合テスト
13. [ ] v0.1.0 タグ + crates.io publish 準備

**Round 2 完了条件**: yotta の日常作業で1週間問題なく動作

## やらないこと（スコープ外）

- Windows / Linux 対応（v0.2+ で検討）
- Cursor 公式対応（マーカー環境変数が提供されるまで待つ）
- kernel-level sandbox（nono 方式、v1+ で検討）
- confirm / rewrite アクション（非TTY + インジェクションリスク）
- SLSA Level 2 / コード署名（OSS 公開時に対応）
- nanika との統合バイナリ化（別ツールとして共存）
- dcg のフォーク・移植（ゼロから設計。ただし dcg のルールセットは参考にする）

## ファイル変更予定

| ファイル/ディレクトリ | 変更内容 |
|---------------------|---------|
| `omamori/` (新規) | Rust プロジェクトルート |
| `omamori/src/main.rs` | エントリポイント（shim モード / CLI モード） |
| `omamori/src/detector.rs` | Detector Providers（trait + claude-code/codex/cursor 実装） |
| `omamori/src/rules.rs` | ルールエンジン |
| `omamori/src/actions/` | 代替動作実装（trash, stash, block, log） |
| `omamori/src/config.rs` | TOML 設定パーサー + デフォルトルール |
| `omamori/src/installer.rs` | PATH shim 配置 + Hooks スクリプト生成 |
| `omamori/config.default.toml` | デフォルト設定ファイル |
| `omamori/src/audit.rs` | 監査ログ（privacy-preserving schema） |
| `omamori/SECURITY.md` | 構造的限界の正直な開示 + 保護対象/非対象コマンド一覧 |
| `~/.claude/settings.json` | omamori Hooks 追加（yotta 環境テスト時） |

## リスクと対策

| リスク | 影響度 | 対策 |
|--------|--------|------|
| /bin/rm フルパス指定で shim 回避（T12, DREAD 9.2） | Critical | Hooks 第2防御層 + SECURITY.md で限界を開示 |
| プロンプトインジェクションで shim 無効化（T13） | High | 「無効化フラグ」を設けない設計。env var unset を Hooks で検知 |
| OSSサプライチェーン攻撃（T14） | High | v0.1 は yotta 環境のみ。OSS 公開時に署名・SLSA 対応 |
| sudo 環境での意図せぬ動作（T11） | High | sudo 検出時は block + 警告ログ（Codex②指摘で「無効化」から「block」に変更） |
| dcg に機能で追いつけない（669 stars の先行者） | High | 差別化3点に集中: マルチツール / nanika 統合 / ポリシーテスト |
| Anthropic がネイティブで全カバー（Sherlocking） | High | Two-way Door。学びが残る。ネイティブが十分なら Celebrate Killing |
| rewrite / stash-then-exec でのコマンドインジェクション | Medium | rewrite は v0.1 除外。stash-then-exec は引数を直接 exec に渡す（シェル展開しない） |
| 大量ファイルの trash でパフォーマンス劣化 | Medium | ファイル数閾値を設定に追加。超過時は block にフォールバック |
| 設定ファイル改竄（T3） | Medium | パーミッション 600 検証 + 所有者チェック |

## 成功指標

- [ ] `CLAUDECODE=1` 環境で `rm -rf` が trash に置換される
- [ ] 環境変数なしの直叩きで `rm -rf` がそのまま実行される
- [ ] `/bin/rm` 直指定を Claude Code Hooks 層で検知・ブロック
- [ ] `unset CLAUDECODE` の回避策が Hooks 層でブロック
- [ ] TOML 設定の追加だけで新ルールを定義可能
- [ ] `omamori test` でルールの発火を検証可能
- [ ] shim クラッシュ時に fail-open で元コマンド実行
- [ ] 設定破損時に fail-close でデフォルトルール適用
- [ ] 既存の nanika / secret-guard Hooks と競合しない
- [ ] yotta の日常作業で1週間問題なく動作

### 定量メトリクス（Codex②指摘で追加）

| メトリクス | 目標値 | 測定方法 |
|-----------|--------|---------|
| 誤検知率（直叩きで発動） | 0% | 1週間の日常作業中の false positive 件数 |
| 見逃し率（AI経由で素通し） | 0% | omamori test の全ルールパス率 |
| shim オーバーヘッド | < 10ms | 非AI環境での time rm vs time omamori-shim-rm |
| 回避検知率（Hooks層） | 80%+ | /bin/rm, unset CLAUDECODE 等の検知テスト |

## 市場調査結果

### Market Research 判定

- **判定**: CONDITIONAL GO
- **主要競合**: dcg（669 stars, Rust製, Claude Code専用, 最終commit 2025-01）
- **プラットフォームリスク**: 高（Anthropic sandbox-runtime 統合中）
- **Why Now**: AI Agent 普及 + 実インシデント多発（rm -rf Mac全消去 HN 172点, Replit DB削除）
- **レッドフラグ**: 5/10
- **グリーンフラグ**: 6/8

### 差別化戦略

| # | 差別化ポイント | dcg の状態 | omamori の提案 |
|---|--------------|-----------|----------------|
| 1 | マルチツール対応 | Claude Code 専用 | env var gate で Claude Code + Codex + Cursor 統一対応 |
| 2 | nanika 統合 | スタンドアロン | nanika（翻訳）+ omamori（置換）のパイプライン |
| 3 | ポリシーテスト | 設定のみ | `omamori test` で発火検証可能 |

### Celebrate Killing 条件

以下のいずれかが確認されたら、プロジェクトの中止を良い判断として扱う:
- dcg がアクティブにメンテされ、マルチツール対応を実装した場合
- Claude Code ネイティブ sandbox が危険コマンドを十分にカバーした場合
- v0.1 テストで yotta の日常作業に支障が出た場合（DX劣化）

## 調査・レビュー結果（/develop への申し送り）

### Codexレビュー①結果

- 指摘事項: 6件（全て対応済みまたは注記）
- ループ回数: 0
- 判定: CONDITIONAL GO（dcg との差別化が最大論点）
- 追加リスク: rewrite のコマンドインジェクション（v0.1 除外で対応）、TOCTOU（実装時に対策）、curl|bash インストーラのサプライチェーンリスク

### QA Shift-left結果

#### 重点検証ポイント
- [ ] 直叩きで shim が発動しないことを複数環境で確認（最重要）
- [ ] 設定ファイル破損時に fail-close になること
- [ ] trash 失敗時に元の rm が実行されないこと
- [ ] brew upgrade で設定が壊れないこと

#### 想定エッジケース
- /bin/rm フルパス指定（構造的限界、Hooks で補完）
- sudo rm（secure_path で PATH 非継承、仕様制限として文書化）
- \rm, command rm（shim はバイナリなのでエイリアス回避構文は通過するが、PATH 上の shim は通る → 要実機確認）
- find -exec, xargs 経由（非TTY で confirm 不可 → confirm を v0.1 除外した理由の1つ）
- 大量ファイル trash（node_modules 等のパフォーマンス → 閾値設定で対応）

#### TDD 先行テストケース
1. AI 環境変数あり + `rm file.txt` → trash 移動が実行される
2. AI 環境変数なし + `rm file.txt` → 素通し（通常の rm が実行される）
3. 設定ファイル破損 → fail-close（デフォルトルールでブロック）
4. trash 失敗 → エラー返却（元の rm を実行しない）
5. ファイルパスにスペース・特殊文字 → 引数が正しく渡される
6. /bin/rm フルパス指定 → PATH shim を回避する（仕様制限の確認テスト）

### Security Threat Model結果

#### 保護対象
| 資産 | 重要度 |
|------|--------|
| ユーザーのファイルシステム | Critical |
| Git リポジトリ状態 | Critical |
| shim バイナリ本体 | Critical |
| ファイルパーミッション | High |
| 設定ファイル | High |
| 操作ログ | Medium |

#### 主要脅威と対策
| 脅威 | DREADスコア | 対策 |
|------|-------------|------|
| T12: フルパス呼び出し回避 | 9.2 | Hooks 第2防御層 + SECURITY.md 開示 |
| T14: サプライチェーン攻撃 | 8.4 | OSS 公開時に署名・SLSA 対応 |
| T11: sudo 権限昇格 | 8.0 | EUID 検出、sudo 時は block + 警告ログ |
| T13: プロンプトインジェクション | 8.0 | 無効化フラグを設けない設計 |
| T1: 環境変数偽装 | 8.2 | 単体を唯一の根拠にしない（Hooks 補完） |

#### セキュリティ要件（/develop への申し送り）
- [ ] 「無効化フラグ」（env var で off にする仕組み）を設けない
- [ ] 設定ファイルのパーミッション 600 検証を起動時に実施
- [ ] 設定ファイル内のパスは canonical 化 + ホワイトリスト検証
- [ ] ログに引数の値（ファイル内容）を記録しない
- [ ] sudo 実行を EUID で検出し、block + 警告ログ出力（全箇所 block で統一済み）
- [ ] stash-then-exec は引数を exec に直接渡す（シェル展開しない）
- [ ] SECURITY.md で「防げるもの / 防げないもの」を初稿から明示

#### 保護対象/非対象コマンド一覧（SECURITY.md に記載、Codex②指摘で追加）

**v0.1 で保護するコマンド:**
| コマンド | パターン | デフォルトアクション |
|---------|---------|-------------------|
| `rm` | `-r`, `-rf`, `-fr`, `--recursive` | trash |
| `git` | `reset --hard` | stash-then-exec |
| `git` | `push --force`, `push -f` | block |
| `git` | `clean -fdx`, `clean -fd` | block |
| `chmod` | `777` | block |

**v0.1 で保護しないもの（構造的限界として文書化）:**
- フルパス指定（`/bin/rm`, `/usr/bin/git`）→ Hooks 層で部分補完
- `sudo` 経由 → block で対応（secure_path で PATH が変わるため shim は発動しない）
- 別言語インタプリタ経由（`python -c "import os; os.remove(...)"`, `perl -e`）
- パイプ経由（`echo "rm -rf /" | sh`）→ Hooks 層で部分補完
- `find -delete`, `rsync --delete` 等の非 rm 削除コマンド

#### 監査ログスキーマ（privacy-preserving、Codex②指摘で追加）

```json
{
  "timestamp": "2026-03-13T10:30:00Z",
  "provider": "claude-code",
  "command": "rm",
  "rule_id": "rm-recursive",
  "action": "trash",
  "result": "success",
  "target_count": 3,
  "target_hash": "sha256:abc123..."
}
```

- `target_hash`: ファイルパスの SHA256 ハッシュ（再現性のため。パス自体は記録しない）
- `target_count`: 対象ファイル/ディレクトリ数（ボリューム感の把握用）
- 引数の値（ファイル名、パス）は一切記録しない

#### 残存リスク
| リスク | 受容理由 |
|--------|---------|
| フルパス呼び出し回避 | PATH shim の構造的限界。kernel-level は OSS 配布に非現実的 |
| プロンプトインジェクション | shim は LLM コンテキストにアクセス不可。AI ツール側の問題 |
| 環境変数判定の精度限界 | userspace 制約。Hooks 補完で軽減 |
| マルチユーザー環境 | 単一ユーザー macOS が対象。サーバー環境は非対応 |

## 修正履歴

| 日付 | フェーズ | 修正内容 | 理由 |
|------|---------|---------|------|
| 2026-03-13 | Phase 4 初稿 | - | 全 Subagent + Codex①結果を統合 |
| 2026-03-13 | Phase 6 修正 | Detector Providers 抽象化、fail-close マトリクス詳細化、sudo 時 block に変更、監査ログスキーマ追加、保護対象/非対象一覧追加、実装順並び替え（ルール/テスト先行）、定量メトリクス追加 | Codex②指摘 7件を反映 |
