# v0.6.0 shell-words PoC Results

Date: 2026-03-22
Issue: #30 Recursive Unwrap Stack
Crate: `shell-words` v1.1.1

## Purpose

Validate design assumptions in `.claude/plans/2026-03-22-v060-recursive-unwrap-stack.md` before `/develop`.

## Key Findings

### 1. Compound operators — pre-split is REQUIRED

shell-words does NOT recognize `&&`, `||`, `;`, `|` as operators. They are only separated when surrounded by whitespace.

```
"a&&b"      → ["a&&b"]          ← 1 token (NOT split)
"a && b"    → ["a", "&&", "b"]  ← 3 tokens (split by whitespace)
"a&&b||c;d" → ["a&&b||c;d"]     ← 1 token
```

**Impact**: Pre-split normalization before `shell_words::split()` is mandatory. Plan already specifies this.

### 2. Unclosed quotes — Err (not panic)

```
"unclosed 'quote"  → Err("missing closing quote")
"unclosed \"quote" → Err("missing closing quote")
```

**BUT backtick is NOT a quote in shell-words:**
```
"unclosed `command" → ["unclosed", "`command"]  ← OK, no error
```

**Impact**: Backtick detection must be done at string level, not via shell-words error. Plan already specifies string-level check for `$(` and backtick.

### 3. env KEY=VAL — single token, as expected

```
"env NODE_ENV=production npm start" → ["env", "NODE_ENV=production", "npm", "start"]
"env TERM=xterm LANG=ja sudo rm"   → ["env", "TERM=xterm", "LANG=ja", "sudo", "rm"]
"env -i rm -rf /"                   → ["env", "-i", "rm", "-rf", "/"]
"env -- rm -rf /"                   → ["env", "--", "rm", "-rf", "/"]
```

**Impact**: `KEY=VAL` regex match on individual tokens works correctly. Plan's env special handling is validated.

### 4. Shell launcher -c — `-lc` stays combined

```
"bash -c 'rm -rf /'"       → ["bash", "-c", "rm -rf /"]
"bash --norc -c 'rm -rf /'" → ["bash", "--norc", "-c", "rm -rf /"]
"bash -lc 'rm -rf /'"      → ["bash", "-lc", "rm -rf /"]  ← NOT split!
```

**Impact**: `-c` detection needs `token == "-c"` OR `token.ends_with("c") && token.starts_with("-") && token.len() > 1` for combined flags like `-lc`. Implementation detail for /develop.

**Bonus**: Inner string quotes are automatically stripped:
```
"bash -c 'rm -rf /'" → inner = "rm -rf /" (no quotes)
```
This means recursive `shell_words::split(inner)` works directly.

### 5. $(...) — preserved as string literal

```
"bash -c \"echo $(rm -rf /)\"" → ["bash", "-c", "echo $(rm -rf /)"]
"bash -c \"$(echo test)\""     → ["bash", "-c", "$(echo test)"]
```

**Impact**: `$(` detection via string contains check on inner token works. Plan validated.

### 6. Quote-splitting bypass — auto-normalized!

```
"om\"\"amori config disable" → ["omamori", "config", "disable"]  ← normalized!
"r\\m -rf /"                 → ["rm", "-rf", "/"]                ← backslash removed!
```

**Impact**: Security threats T1 (homoglyph) and T6 (backslash) are partially mitigated by shell-words itself. This is better than expected.

### 7. Spawn latency — well within budget

```
avg: 3.33ms
p50: 3.27ms
p95: 3.96ms
p99: 5.17ms
max: 7.45ms
```

**Impact**: p95 = 3.96ms, budget = 10ms. ~6ms headroom for parse logic. No concern.

## Plan Impact Assessment

| Finding | Plan needs change? | Reason |
|---------|-------------------|--------|
| Compound pre-split required | No | Already specified |
| Backtick not an error | No | String-level check already specified |
| env KEY=VAL works | No | Validated as designed |
| `-lc` combined flag | No (impl detail) | "任意位置の -c" covers this |
| $() preserved | No | Validated as designed |
| Quote bypass normalized | No (positive surprise) | Risk reduced |
| Latency OK | No | Within budget |

**Conclusion**: All design assumptions validated. No plan modifications required. Proceed to /develop.

## PoC Source

`examples/unwrap_poc.rs` (preserved for reference, remove before release)
