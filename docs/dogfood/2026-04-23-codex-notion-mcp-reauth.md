# 2026-04-23 Codex による Notion MCP 再認証で omamori hook が発火した実録

## 概要

Codex CLI で Notion MCP の再認証 (`codex mcp login notion`) を実行した際、
Codex が事前調査として `~/.codex/config.toml` を読もうとして、omamori hook が
複数段にわたって阻止した実ログ。v0.9.5 で強化した Codex config 保護と
oracle attack prevention (wrapper-evasion 対策) が本番で機能することを確認した。

## シナリオ

- ユーザー: yotta
- AI エージェント: Codex CLI
- 目的: Notion MCP の OAuth 再認証
- 環境: omamori v0.9.5 (2026-04-20 release) が有効

## 実ログ抜粋

### 1. Codex の調査意図

```
Notion MCP の認証設定を確認して、再認証に使うコマンドか設定箇所を特定する。
まず config.toml と notion 関連の定義を読む。
```

### 2. omamori hook が直接参照を阻止

```
PreToolUse hook (blocked)
feedback: omamori hook: blocked — blocked attempt to edit Codex config
hint: run `omamori explain -- rg -n "notion|mcp" /Users/i.yoshida/.codex/config.toml .codex AGENTS.md` for details

PreToolUse hook (blocked)
feedback: omamori hook: blocked — blocked attempt to edit Codex config
hint: run `omamori explain -- sed -n '1,220p' /Users/i.yoshida/.codex/config.toml` for details
```

`rg` / `sed` による Codex config の直接参照はどちらも `blocked` で停止。

### 3. omamori explain ネストによる bypass 試行も阻止

```
PreToolUse hook (blocked)
feedback: omamori hook: blocked — blocked attempt to run explain via AI (oracle attack prevention)
hint: run `omamori explain -- omamori explain -- sed -n '1,220p' /Users/i.yoshida/.codex/config.toml` for details
```

hint として示された `omamori explain -- ...` を Codex がそのまま実行しようとしたが、
oracle attack prevention が起動してネストを弾いた。

### 4. Codex が別経路へ転換

```
設定読取は保護されているので、Codex CLI 側の再認証導線を探す。
codex のヘルプから Notion/MCP の認証サブコマンドを確認する。
```

その後、`codex mcp --help` → `codex mcp list` → `codex mcp login notion` で
OAuth フローを起動し、ブラウザ認可で再認証完了。

## 観察ポイント

### 狙い通りに動いた箇所

| 挙動 | 評価 |
|------|------|
| `rg` による config.toml 参照をブロック | OK |
| `sed` による config.toml 参照をブロック | OK |
| `omamori explain -- omamori explain -- ...` のネストをブロック | OK (oracle attack prevention) |
| hint を出して yotta 本人が後追い検証できる経路を残した | OK |

### v0.9.5 の wrapper-evasion 対策との関連

v0.9.5 Phase 6-A で Codex が 8 ラウンドかけて unwrap.rs を攻めた結果、
`bash -s ARG` / `|&` / option-value flags / `command -v/-V` introspection 等の
bypass 経路を全て塞いだ。今回のログは、そのあとで別の AI が実運用で
config 読取を試みたら、すべて検知側が先に反応する状態になっていることを
裏付けている。

### 設計意図の確認

- 「AI から Codex config を読ませない」 → **達成**
- 「別 AI が omamori explain を oracle として使うのを防ぐ」 → **達成**
- 「yotta 本人の後追いデバッグ経路は残す (hint)」 → **達成**

## 補足: omamori 起因ではない周辺ノイズ

同じ transcript に以下のエラーも混在していたが、これは omamori 由来ではなく
Codex 側の hook 設定問題として分離整理した。

```
UserPromptSubmit hook (failed) error: hook exited with code 127
PreToolUse hook (failed) error: PreToolUse hook returned unsupported permissionDecision:allow
```

- exit 127 = command not found (Codex の hook 定義内で参照されている別コマンドが PATH 解決失敗)
- `permissionDecision:allow` = Codex hook API が受け付けない値 (Claude Code の hook API と仕様差)

## 引用用途

この実録は今後以下の用途で引用可能:

- omamori README の「実運用での効果」セクション
- v1.0 に向けた dogfooding 証跡
- ブログ記事「他 AI に自分の設定を覗かせない」の素材
- 外部レビュー・監査時の挙動エビデンス

## 関連

- v0.9.5 plan: `investigation/` 配下の Codex Phase 6-A ログ
- SECURITY.md: wrapper-evasion 対策
- unwrap.rs: bash wrapper 攻撃面の網羅実装
