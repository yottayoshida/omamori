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
        Some(other) => Err(AppError::Usage(format!(
            "unknown audit subcommand: {other}\n\n{}",
            audit_usage()
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
            "--json" => {
                opts.json = true;
                index += 1;
            }
            other => {
                return Err(AppError::Usage(format!(
                    "unknown show flag: {other}\n\n{}",
                    audit_usage()
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

fn run_audit_key(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(3).and_then(|item| item.to_str()) {
        Some("rotate") => {
            guard_ai_config_modification("audit key rotate")?;

            let load_result = load_config(None)?;
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
            "unknown audit key subcommand: {other}\n\n{}",
            audit_usage()
        ))),
        None => Err(AppError::Usage(format!(
            "audit key requires a subcommand\n\n{}",
            audit_usage()
        ))),
    }
}

fn audit_usage() -> &'static str {
    "omamori audit — audit log commands

  omamori audit verify                           Verify hash chain integrity
  omamori audit show [--last N] [--json]         View recent audit entries (default: last 20)
  omamori audit show --all                       View all entries
  omamori audit show --rule <name>               Filter by rule (substring match)
  omamori audit show --provider <name>           Filter by provider
  omamori audit key rotate                       Rotate HMAC signing key"
}
