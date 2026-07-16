//! `omamori audit verify/show/key` subcommands.

use std::ffi::OsString;

use crate::AppError;
use crate::audit;
use crate::config::load_config;
use crate::engine::guard::guard_ai_config_modification;
use crate::util::parse_config_flag;

pub(crate) fn run_audit_command(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(2).and_then(|item| item.to_str()) {
        Some("verify") => run_audit_verify(args),
        Some("show") => run_audit_show(args),
        Some("key") => run_audit_key(args),
        Some("hash-cwd") => run_audit_hash_cwd(args),
        // PR6 (#182): surface unknown-tool fail-open events.
        // Sugar over `audit show --action unknown_tool_fail_open --all`.
        Some("unknown") => run_audit_unknown(args),
        Some(other) => Err(AppError::Usage(format!(
            "unknown audit subcommand: {other}\n\n{AUDIT_USAGE_HINT}"
        ))),
        None => {
            eprintln!("{}", audit_usage());
            Ok(0)
        }
    }
}

fn run_audit_verify(args: &[OsString]) -> Result<i32, AppError> {
    let config_path = parse_config_flag(&args[3..])?;
    let load_result = load_config(config_path.as_deref())?;

    match audit::verify_chain(&load_result.config.audit) {
        Ok(result) => {
            if let Some(seq) = result.broken_at {
                eprintln!("omamori audit verify: chain broken at entry #{seq}");
                eprintln!("  The audit log may have been tampered with.");
                eprintln!("  Inspect: omamori audit show --last 10");
                Ok(1)
            } else if result.chain_entries == 0 && result.legacy_entries > 0 {
                eprintln!(
                    "omamori audit verify: no chain entries found ({} legacy entries skipped)",
                    result.legacy_entries
                );
                Ok(2)
            } else if result.chain_entries == 0 {
                println!("omamori audit verify: no entries to verify.");
                Ok(0)
            } else {
                let mut msg = format!(
                    "omamori audit verify: {} entries verified, chain intact.",
                    result.chain_entries
                );
                if result.pruned
                    && let Some(count) = result.pruned_count
                {
                    msg.push_str(&format!(" ({count} entries pruned; prune_point anchored)"));
                }
                if result.legacy_entries > 0 {
                    msg.push_str(&format!(" ({} legacy skipped)", result.legacy_entries));
                }
                if result.torn_lines > 0 {
                    msg.push_str(&format!(" ({} torn lines skipped)", result.torn_lines));
                }
                println!("{msg}");
                if result.tail_truncated {
                    eprintln!(
                        "  WARNING: audit log tail may have been truncated \
                         (chain ends before high-water-mark)."
                    );
                    eprintln!("  Inspect: omamori audit show --last 20");
                    return Ok(3);
                }
                if result.hwm_tampered {
                    eprintln!(
                        "  WARNING: high-water-mark file was unreadable or tampered with \
                         (expected a plain integer, found a symlink or invalid content)."
                    );
                    eprintln!(
                        "  It has been reset to the current chain end, but this may indicate \
                         an attempt to defeat tail-truncation detection."
                    );
                    return Ok(3);
                }
                if result.hwm_missing {
                    eprintln!("  Note: high-water-mark bootstrapped to current chain end.");
                }
                Ok(0)
            }
        }
        Err(audit::AuditError::SecretUnavailable) => {
            eprintln!("omamori audit verify: cannot verify \u{2014} HMAC secret unavailable");
            Ok(2)
        }
        Err(audit::AuditError::FileNotFound) => {
            eprintln!("omamori audit verify: no audit log found");
            Ok(2)
        }
        Err(audit::AuditError::Io(e)) => {
            eprintln!("omamori audit verify: {e}");
            Ok(2)
        }
    }
}

fn run_audit_show(args: &[OsString]) -> Result<i32, AppError> {
    let mut opts = audit::ShowOptions {
        last: Some(20),
        rule: None,
        provider: None,
        json: false,
        action: None,
        relaxed_only: false,
    };

    let mut index = 3usize;
    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--last" => {
                let value = args
                    .get(index + 1)
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| AppError::Usage("--last requires a number".to_string()))?;
                opts.last =
                    Some(value.parse::<usize>().map_err(|_| {
                        AppError::Usage(format!("invalid number for --last: {value}"))
                    })?);
                index += 2;
            }
            "--all" => {
                opts.last = None;
                index += 1;
            }
            "--rule" => {
                opts.rule = Some(
                    args.get(index + 1)
                        .and_then(|v| v.to_str())
                        .ok_or_else(|| AppError::Usage("--rule requires a value".to_string()))?
                        .to_string(),
                );
                index += 2;
            }
            "--provider" => {
                opts.provider = Some(
                    args.get(index + 1)
                        .and_then(|v| v.to_str())
                        .ok_or_else(|| AppError::Usage("--provider requires a value".to_string()))?
                        .to_string(),
                );
                index += 2;
            }
            "--action" => {
                opts.action = Some(
                    args.get(index + 1)
                        .and_then(|v| v.to_str())
                        .ok_or_else(|| AppError::Usage("--action requires a value".to_string()))?
                        .to_string(),
                );
                index += 2;
            }
            "--json" => {
                opts.json = true;
                index += 1;
            }
            "--relaxed" => {
                opts.relaxed_only = true;
                index += 1;
            }
            other => {
                return Err(AppError::Usage(format!(
                    "unknown show flag: {other}\n\n{AUDIT_USAGE_HINT}"
                )));
            }
        }
    }

    let load_result = load_config(None)?;
    let mut stdout = std::io::stdout().lock();
    match audit::show_entries(&load_result.config.audit, &opts, &mut stdout) {
        Ok(()) => Ok(0),
        Err(audit::AuditError::FileNotFound) => {
            println!("omamori audit: no entries recorded yet");
            Ok(0)
        }
        Err(e) => {
            eprintln!("omamori audit show: {e}");
            Ok(1)
        }
    }
}

/// `omamori audit unknown` — show all `unknown_tool_fail_open` events.
///
/// This is the user-facing review surface promised in the stderr hint
/// emitted by the hook layer when a tool drifts past structure-based
/// routing. We default to `--all` so users see every fail-open since
/// the audit log started; `--last N` and `--json` work the same as
/// `audit show`.
fn run_audit_unknown(args: &[OsString]) -> Result<i32, AppError> {
    let mut opts = audit::ShowOptions {
        last: None, // default --all so review is complete
        rule: None,
        provider: None,
        json: false,
        action: Some("unknown_tool_fail_open".to_string()),
        relaxed_only: false,
    };

    let mut index = 3usize;
    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--last" => {
                let value = args
                    .get(index + 1)
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| AppError::Usage("--last requires a number".to_string()))?;
                opts.last =
                    Some(value.parse::<usize>().map_err(|_| {
                        AppError::Usage(format!("invalid number for --last: {value}"))
                    })?);
                index += 2;
            }
            "--json" => {
                opts.json = true;
                index += 1;
            }
            other => {
                return Err(AppError::Usage(format!(
                    "unknown 'audit unknown' flag: {other}\n\n{AUDIT_USAGE_HINT}"
                )));
            }
        }
    }

    let load_result = load_config(None)?;
    let mut stdout = std::io::stdout().lock();
    match audit::show_entries(&load_result.config.audit, &opts, &mut stdout) {
        Ok(()) => Ok(0),
        Err(audit::AuditError::FileNotFound) => {
            println!("omamori audit: no entries recorded yet");
            Ok(0)
        }
        Err(e) => {
            eprintln!("omamori audit unknown: {e}");
            Ok(1)
        }
    }
}

/// `audit::rotate_key` falls back to `secret::default_audit_path`
/// internally when `config.path` is unset (that fallback lives in a file
/// this codebase cannot edit — see #306/#323). That fallback resolves
/// against the current working directory when `HOME` is unset, empty, or
/// relative. Returns `true` when rotation would hit that CWD-relative
/// fallback, so the caller can refuse up front instead.
fn rotate_key_would_use_cwd_fallback(config: &audit::AuditConfig) -> bool {
    config.path.is_none() && crate::context::home_dir().is_none()
}

fn run_audit_key(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(3).and_then(|item| item.to_str()) {
        Some("rotate") => {
            guard_ai_config_modification("audit key rotate")?;

            let load_result = load_config(None)?;

            if rotate_key_would_use_cwd_fallback(&load_result.config.audit) {
                eprintln!("omamori: cannot resolve audit path — HOME is unset, empty, or relative");
                eprintln!("  set audit.path explicitly in config.toml, or fix HOME, and retry");
                return Ok(1);
            }

            eprintln!("omamori: rotating audit HMAC key...");
            eprintln!("  Old entries will still verify against the retired key backup.");

            match audit::rotate_key(&load_result.config.audit) {
                Ok(result) => {
                    eprintln!("omamori: key rotation complete.");
                    eprintln!("  New key ID: {}", result.new_key_id);
                    eprintln!("  Retired key: {}", result.retired_path.display());
                    eprintln!("  Run `omamori audit verify` to confirm chain integrity.");
                    Ok(0)
                }
                Err(audit::AuditError::SecretUnavailable) => {
                    eprintln!("omamori: no audit secret found — nothing to rotate");
                    Ok(1)
                }
                Err(e) => {
                    eprintln!("omamori: key rotation failed: {e}");
                    Ok(1)
                }
            }
        }
        Some(other) => Err(AppError::Usage(format!(
            "unknown audit key subcommand: {other}\n\n{AUDIT_USAGE_HINT}"
        ))),
        None => Err(AppError::Usage(format!(
            "audit key requires a subcommand\n\n{AUDIT_USAGE_HINT}"
        ))),
    }
}

const AUDIT_USAGE_HINT: &str = "Run `omamori audit` for usage.";

fn audit_usage() -> &'static str {
    "omamori audit — audit log commands

  omamori audit verify                           Verify hash chain integrity
  omamori audit show [--last N] [--json]         View recent audit entries (default: last 20)
  omamori audit show --all                       View all entries
  omamori audit show --rule <name>               Filter by rule (substring match)
  omamori audit show --provider <name>           Filter by provider
  omamori audit show --action <name>             Filter by action (exact match)
  omamori audit show --relaxed                   Filter to relaxed allows (legacy data-context flag; pre-v0.10.4 logs only)
  omamori audit unknown [--last N] [--json]      Show forward-compat fail-opens for unknown tools (#182)
  omamori audit key rotate                       Rotate HMAC signing key
  omamori audit hash-cwd <path>                  Hash a candidate directory to match against cwd_hash in the log (#420)"
}

/// `omamori audit hash-cwd <path>` — an investigator's forensic tool (#420).
/// `cwd_hash` in the log is a domain-separated HMAC, so a candidate path
/// can't be checked for a match by eye; this computes every hash a real
/// entry could plausibly have used for that path and lets the investigator
/// grep the log for any of them. "Every hash" spans two axes:
///
/// - **Key**: `secret::load_keyring` returns the active key plus any
///   retired ones, since a key rotation could have happened between when
///   the entry was written and now.
/// - **Path form**: `AuditEvent.cwd_hash` is computed from
///   `std::env::current_dir()`, which returns an already symlink-resolved
///   path (e.g. macOS `/tmp` → `/private/tmp`). An investigator's hand-typed
///   candidate is typically NOT resolved, so both the raw and canonicalized
///   forms of the candidate are hashed — trying only one silently misses
///   the other.
fn run_audit_hash_cwd(args: &[OsString]) -> Result<i32, AppError> {
    let path_arg = args.get(3).and_then(|item| item.to_str()).ok_or_else(|| {
        AppError::Usage(format!(
            "audit hash-cwd requires a path argument\n\n{AUDIT_USAGE_HINT}"
        ))
    })?;
    let candidate = std::path::PathBuf::from(path_arg);

    let load_result = load_config(None)?;
    match audit::hash_cwd_candidates(&load_result.config.audit, &candidate) {
        Some(candidates) => {
            println!("Candidate cwd_hash values for {}:", candidate.display());
            for (key_id, form, hash) in candidates {
                println!("  [{key_id}, {form}] {hash}");
            }
            println!();
            println!("Grep the audit log for any of the above cwd_hash values.");
            Ok(0)
        }
        None => {
            eprintln!(
                "omamori audit hash-cwd: no audit path or HMAC secret available — nothing to hash against"
            );
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // V-012: audit error paths use short hint, not full audit_usage() dump

    #[test]
    fn unknown_audit_subcommand_uses_hint() {
        let args: Vec<OsString> = vec!["omamori".into(), "audit".into(), "bogus".into()];
        let err = run_audit_command(&args).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(AUDIT_USAGE_HINT), "should use short hint");
        assert!(
            !msg.contains("omamori audit verify"),
            "should not dump full audit usage"
        );
    }

    #[test]
    fn unknown_show_flag_uses_hint() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--bogus".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(AUDIT_USAGE_HINT));
    }

    #[test]
    fn audit_no_subcommand_shows_full_usage() {
        let args: Vec<OsString> = vec!["omamori".into(), "audit".into()];
        let code = run_audit_command(&args).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn unknown_audit_key_subcommand_uses_hint() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "key".into(),
            "bogus".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(AUDIT_USAGE_HINT));
    }

    #[test]
    fn audit_key_no_subcommand_uses_hint() {
        let args: Vec<OsString> = vec!["omamori".into(), "audit".into(), "key".into()];
        let err = run_audit_command(&args).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(AUDIT_USAGE_HINT));
    }

    // -----------------------------------------------------------------
    // run_audit_hash_cwd (#420, Codex proxy review Round 1 P2 —
    // args.get(3) extraction, missing-arg Usage branch, and the
    // None -> Ok(1) branch had zero coverage prior to this PR)
    // -----------------------------------------------------------------

    #[test]
    fn hash_cwd_missing_path_arg_uses_hint() {
        let args: Vec<OsString> = vec!["omamori".into(), "audit".into(), "hash-cwd".into()];
        let err = run_audit_command(&args).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(AUDIT_USAGE_HINT));
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn hash_cwd_returns_one_when_no_keyring_exists() {
        let dir =
            std::env::temp_dir().join(format!("omamori-hashcwd-cli-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let dir_str = dir.to_str().unwrap().to_string();
        let code = crate::test_support::with_home(Some(&dir_str), || {
            // Deliberately no AuditLogger::from_config call — no secret has
            // ever been created under this HOME, so the keyring is empty.
            let args: Vec<OsString> = vec![
                "omamori".into(),
                "audit".into(),
                "hash-cwd".into(),
                dir_str.clone().into(),
            ];
            run_audit_command(&args).unwrap()
        });
        assert_eq!(code, 1, "no keyring exists yet — must return exit code 1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn hash_cwd_returns_zero_when_keyring_exists() {
        let dir =
            std::env::temp_dir().join(format!("omamori-hashcwd-cli-some-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let dir_str = dir.to_str().unwrap().to_string();
        let code = crate::test_support::with_home(Some(&dir_str), || {
            // Establish a real secret at the HOME-derived default audit
            // path, mirroring what a real `omamori` invocation would have
            // done before an investigator ever runs `hash-cwd`.
            let config = audit_config(None);
            let _logger = audit::AuditLogger::from_config(&config).expect("logger constructs");

            let args: Vec<OsString> = vec![
                "omamori".into(),
                "audit".into(),
                "hash-cwd".into(),
                dir_str.clone().into(),
            ];
            run_audit_command(&args).unwrap()
        });
        assert_eq!(code, 0, "keyring exists — must return exit code 0");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // rotate_key_would_use_cwd_fallback (#306/#323 residual — Codex R1 P0)
    // -----------------------------------------------------------------

    use crate::test_support::with_home;

    fn audit_config(path: Option<std::path::PathBuf>) -> audit::AuditConfig {
        audit::AuditConfig {
            enabled: true,
            path,
            retention_days: 0,
            strict: false,
        }
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn rotate_guard_true_when_no_override_and_home_unusable() {
        let config = audit_config(None);
        assert!(with_home(Some(""), || rotate_key_would_use_cwd_fallback(
            &config
        )));
        assert!(with_home(None, || rotate_key_would_use_cwd_fallback(
            &config
        )));
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn rotate_guard_false_when_explicit_path_set() {
        let config = audit_config(Some(std::path::PathBuf::from("/explicit/audit.jsonl")));
        assert!(!with_home(Some(""), || rotate_key_would_use_cwd_fallback(
            &config
        )));
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn rotate_guard_false_when_home_absolute() {
        let config = audit_config(None);
        assert!(!with_home(Some("/tmp/omamori-rotate-guard-test"), || {
            rotate_key_would_use_cwd_fallback(&config)
        }));
    }

    #[test]
    fn unknown_audit_unknown_flag_uses_hint() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "unknown".into(),
            "--bogus".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(AUDIT_USAGE_HINT));
    }
}
