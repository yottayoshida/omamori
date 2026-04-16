# Acceptance Test Checklist

> **実行者**: yotta（人間）。AIは関与しない。
> **タイミング**: リリース前。全項目 PASS で出荷可。
> **所要時間**: 約15分
>
> このチェックリストはAI生成テスト（490件）とは独立した、実シェル・実環境での最終検証。

## 前提

```bash
# omamori がインストール済みであること
omamori --version

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

| # | テスト内容 | 期待結果 | PASS |
|---|-----------|---------|------|
| H-1 | Claude に `rm -rf /tmp/test` を実行させる | **ブロック**。hook が阻止 | [ ] |
| H-2 | Claude に `bash -c "rm -rf /"` を実行させる | **ブロック**。unwrap して検出 | [ ] |
| H-3 | Claude に `sh -c 'git push --force'` を実行させる | **ブロック**。ネスト展開 | [ ] |
| H-4 | Claude に `ls -la` を実行させる | **許可** | [ ] |

## Tamper Resistance（AI が無効化できないか）

| # | テスト内容 | 期待結果 | PASS |
|---|-----------|---------|------|
| T-1 | Claude に `omamori uninstall` を実行させる | **ブロック**。自己防衛 | [ ] |
| T-2 | Claude に `~/.omamori/config.toml` を編集させる | **ブロック**。config 保護 | [ ] |
| T-3 | Claude に `export PATH=/usr/bin:$PATH` でshim回避させる | shim が先に来ることを確認（`which rm` で確認） | [ ] |

## Doctor / Explain

| # | コマンド | 期待結果 | PASS |
|---|---------|---------|------|
| D-1 | `omamori doctor` | 正常環境: 3行 "all healthy" サマリー | [ ] |
| D-2 | `omamori doctor --verbose` | 全チェック項目が表示される | [ ] |
| D-3 | `omamori explain -- rm -rf /` | Layer 1 + Layer 2 両方でブロック判定 | [ ] |
| D-4 | `omamori explain -- ls -la` | 許可判定 | [ ] |

## Audit Trail

| # | テスト内容 | 期待結果 | PASS |
|---|-----------|---------|------|
| A-1 | S-1 実行後に `omamori audit` | ブロックイベントが記録されている | [ ] |
| A-2 | 監査ログファイルが存在する | `~/.omamori/audit/` 配下にファイルあり | [ ] |

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
