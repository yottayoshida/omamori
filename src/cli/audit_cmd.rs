//! `omamori audit verify/show/key` subcommands.

use std::ffi::OsString;

use crate::AppError;
use crate::audit;
use crate::audit::KeyUnavailableKind;
use crate::config::load_config;
use crate::engine::guard::guard_ai_config_modification;
use crate::engine::shim::emit_config_warnings;
use crate::util::{flag_value_str, parse_config_flag};

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

/// Builds `omamori audit verify`'s success-path stdout message. Extracted
/// from `run_audit_verify` (#177 B3, Codex Phase 6-B) so the `(N v1 + M v2)`
/// mixed-version parenthetical — and the rest of this message's shape —
/// gets direct unit-test coverage without needing a full CLI subprocess and
/// a signed `audit.jsonl` fixture built from outside the crate.
fn format_verify_success_message(result: &audit::VerifyResult) -> String {
    let mut msg = format!(
        "omamori audit verify: {} entries verified, chain intact.",
        result.chain_entries
    );
    // #177 B3: only surface the version split once a log actually spans
    // the v1→v2 upgrade boundary — a single-version log (the common case,
    // both before and long after upgrading) gets no redundant
    // parenthetical.
    if result.v1_entries > 0 && result.v2_entries > 0 {
        msg.push_str(&format!(
            " ({} v1 + {} v2)",
            result.v1_entries, result.v2_entries
        ));
    }
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
    msg
}

fn run_audit_verify(args: &[OsString]) -> Result<i32, AppError> {
    let config_path = parse_config_flag(&args[3..])?;
    let load_result = load_config(config_path.as_deref())?;
    emit_config_warnings(&load_result);

    match audit::verify_chain(&load_result.config.audit) {
        Ok(result) => {
            // #457: keyring problems are reported whatever the verdict turns
            // out to be. A truncated or partly-unreadable ring changes what
            // "chain intact" actually covers, and a shorter key set that
            // verifies fewer entries is indistinguishable from a complete one
            // unless it is said out loud.
            for warning in &result.keyring_warnings {
                eprintln!("omamori warning: {warning}");
            }
            if let Some(seq) = result.broken_at {
                eprintln!("omamori audit verify: chain broken at entry #{seq}");
                eprintln!("  The audit log may have been tampered with.");
                eprintln!("  Do not delete audit.jsonl — copy it aside first.");
                // #457: a break near the head is common — every chain spanning
                // a key rotation broke at #0 — and `--last 10` shows the tail,
                // the opposite end of the file. Point at where the break is.
                //
                // `--json` is not decoration. The break is identified by seq,
                // and the human table has no seq column (TIMESTAMP / PROVIDER
                // / COMMAND / ACTION / RESULT / RULE), so the plain form
                // cannot answer "which line is #{seq}". `--json` emits one
                // object per line, seq included. `audit show --first`/`--around`
                // would be the better answer and are tracked separately.
                if seq < 10 {
                    eprintln!("  Inspect: omamori audit show --all --json | head -20");
                } else {
                    eprintln!("  Inspect: omamori audit show --last 10 --json");
                }
                Ok(1)
            } else if let (Some(seq), Some(chain_version)) =
                (result.unknown_version_at, result.unknown_chain_version)
            {
                eprintln!(
                    "omamori audit verify: chain entry #{seq} declares chain_version \
                     {chain_version}, which this omamori build does not recognize."
                );
                eprintln!(
                    "  {} entries verified before this point; unable to verify {} \
                     entries at or after it.",
                    result.chain_entries, result.unverified_entries_after
                );
                eprintln!(
                    "  This is not necessarily tampering — it may mean this omamori \
                     binary predates a newer chain format. Upgrade omamori and re-run."
                );
                eprintln!(
                    "  If you are already running the latest omamori, an unrecognized \
                     chain_version is unexpected — treat this as possible tampering. \
                     Tail-truncation detection is suspended while this entry is present."
                );
                Ok(4)
            } else if let (Some(seq), Some(key_id)) = (
                result.key_unavailable_at,
                result.key_unavailable_id.as_deref(),
            ) {
                // #457 A5: exit 2 (cannot verify), not 1 (tampered) and not 4
                // (upgrade omamori). Exit 4's remedy is "install a newer
                // build", which does nothing for a missing key file; exit 1
                // accuses the operator of an attack that did not happen.
                eprintln!(
                    "omamori audit verify: cannot verify from entry #{seq} — it names \
                     key \"{key_id}\", which is not in the keyring."
                );
                eprintln!(
                    "  {} entries verified before this point; unable to verify {} \
                     entries at or after it.",
                    result.chain_entries, result.unverified_entries_after
                );
                // #457 Phase 8: this used to be a flat "This is not evidence
                // of tampering." followed by "the key file is missing" —
                // an exoneration asserted from a field the attacker writes.
                // Each arm below says only what the evidence supports.
                match result.key_unavailable_kind.as_ref() {
                    // "already cleared", not "make the directory readable":
                    // `verify_chain` stops at the fatal keyring anomaly before
                    // it reads any entry, so this arm is only ever reached once
                    // the directory is listable again. The old wording sent the
                    // operator to check a permission that was already correct.
                    //
                    // **Not covered by a test.** Reaching it needs an entry
                    // appended while the epoch could not be resolved, and the
                    // only writers that do that are the shim and hook paths —
                    // no `tests/cli.rs` command appends one (measured: `config
                    // disable` refuses a core rule, `override disable` writes
                    // no audit entry). It belongs in `hook_integration.rs`.
                    Some(KeyUnavailableKind::NeverProtected) => {
                        eprintln!(
                            "  omamori wrote this entry itself, while the key directory could \
                             not be listed, so it carries no HMAC and never did. No key file \
                             is missing and restoring one will not help; the entry stays \
                             unverifiable. The key directory is listable again — this run \
                             just listed it — so the condition that produced this entry \
                             has already cleared."
                        );
                    }
                    Some(KeyUnavailableKind::NotWriterEmitted) => {
                        eprintln!(
                            "  No omamori build writes a key_id of this shape, so a missing \
                             key file does not explain it — this entry's key_id has been \
                             altered. Treat it as possible tampering."
                        );
                    }
                    Some(KeyUnavailableKind::KeyFileAbsent {
                        expected_file,
                        beyond_known_epochs: None,
                    }) => {
                        eprintln!(
                            "  Most likely the key file is missing, renamed, or unreadable: \
                             look for {expected_file}, in the directory holding audit.jsonl, \
                             and re-run."
                        );
                        eprintln!(
                            "  If you did not rename, move or delete a key file, treat this \
                             as possible tampering — key_id is an ordinary field of the log \
                             and editing it produces this same state."
                        );
                    }
                    Some(KeyUnavailableKind::KeyFileAbsent {
                        beyond_known_epochs: Some(highest),
                        ..
                    }) => {
                        // Sending the operator after `audit-secret.99.retired`
                        // on a store that reached epoch 2 wastes their time and
                        // dresses an edit up as their own filing error. State
                        // the observation instead; it is checkable, and it is
                        // the one thing here that is not a guess.
                        eprintln!(
                            "  The highest key epoch this store currently shows is \
                             {highest} — there is no key file for a higher epoch here \
                             to have gone missing."
                        );
                        eprintln!(
                            "  Either this entry's key_id has been altered, or retired key \
                             files were deleted from the directory holding audit.jsonl. \
                             Nothing on disk records the store's epoch history, so omamori \
                             cannot tell those apart. If you did not delete any, treat this \
                             as possible tampering."
                        );
                    }
                    None => {}
                }
                // Parity with the exit-4 branch, which suppresses the same
                // check for the same reason and says so. Omitting it here made
                // exit 2 the quieter of the two states to arrive at.
                eprintln!("  Tail-truncation detection is suspended while this entry is present.");
                Ok(2)
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
                println!("{}", format_verify_success_message(&result));
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
        // #457: an unlistable key directory. Reported as cannot-verify rather
        // than allowed to masquerade as tampering — on a rotated store,
        // continuing would resolve every `"default"` to the active key and
        // fail the whole chain over a permissions problem.
        Err(audit::AuditError::KeyringUnusable(reason)) => {
            eprintln!("omamori audit verify: cannot verify \u{2014} {reason}");
            // "listable", not "check the permissions": the cause is already in
            // `{reason}` above, in one wording, from one constructor
            // (`secret::unlistable`). #477 first tried sharing this sentence
            // across the four sites instead, which put a cause in each of them
            // and made three wrong — rotation also needs the directory
            // *writable*, and the per-entry arm below is only reached once it
            // is readable again. Name the property that failed; let the reason
            // say why.
            eprintln!("  To fix: make that directory listable again, then re-run.");
            Ok(2)
        }
        // #478: `verify_chain` does not produce this — only `rotate_key` does.
        // The arm exists because the match is exhaustive, and it prints rather
        // than panicking: a verifier that aborts on an unexpected variant is
        // worse than one that reports it, and the wording is still specific
        // enough to be traced back here if it ever appears.
        Err(e @ audit::AuditError::RotationInterrupted { .. }) => {
            eprintln!("omamori audit verify: cannot verify \u{2014} {e}");
            Ok(2)
        }
        // No catch-all: `#[non_exhaustive]` constrains other crates, not this
        // one, so the compiler still requires every variant here — which is
        // what should happen. A new failure mode deserves its own wording, not
        // a generic fallback that silently absorbs it.
        Err(audit::AuditError::Io(e)) => {
            // #478: carries the verdict, like every other arm here. Keeping
            // `read_secret`'s error body instead of flattening it routed four
            // more store shapes through this arm — a non-regular secret, an
            // oversize one, unreadable hex, a symlinked path — and each of them
            // arrived as a bare errno with nothing saying what omamori had
            // decided. The reason is more specific than "HMAC secret
            // unavailable" was; it is not a substitute for the verdict.
            eprintln!("omamori audit verify: cannot verify \u{2014} {e}");
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
                let (value, next) =
                    flag_value_str(args, index, || "--last requires a number".to_string())?;
                opts.last =
                    Some(value.parse::<usize>().map_err(|_| {
                        AppError::Usage(format!("invalid number for --last: {value}"))
                    })?);
                index = next;
            }
            "--all" => {
                opts.last = None;
                index += 1;
            }
            "--rule" => {
                let (value, next) =
                    flag_value_str(args, index, || "--rule requires a value".to_string())?;
                opts.rule = Some(value.to_string());
                index = next;
            }
            "--provider" => {
                let (value, next) =
                    flag_value_str(args, index, || "--provider requires a value".to_string())?;
                opts.provider = Some(value.to_string());
                index = next;
            }
            "--action" => {
                let (value, next) =
                    flag_value_str(args, index, || "--action requires a value".to_string())?;
                opts.action = Some(value.to_string());
                index = next;
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
    emit_config_warnings(&load_result);
    let mut stdout = std::io::stdout().lock();
    match audit::show_entries(&load_result.config.audit, &opts, &mut stdout) {
        Ok(()) => Ok(0),
        Err(audit::AuditError::FileNotFound) => {
            println!("omamori audit: no entries recorded yet");
            Ok(0)
        }
        Err(e) if is_broken_pipe(&e) => Ok(0),
        Err(e) => {
            eprintln!("omamori audit show: {e}");
            Ok(1)
        }
    }
}

/// Did the reader on the other end of stdout go away?
///
/// Rust disables the default `SIGPIPE` handler at startup, so `cmd | head -20`
/// does not kill the process the way a C program would — the write returns
/// `EPIPE` and it surfaces as an error. Printing `Broken pipe (os error 32)`
/// and exiting 1 for what is a normal, deliberate way to read a long log is
/// wrong, and #457 made it worse by adding a recovery hint (`audit show --all
/// | head -20`) that walks straight into it: measured, that exact command
/// printed the error whenever the log outgrew the pipe buffer — which is
/// precisely when a user would reach for it.
fn is_broken_pipe(e: &audit::AuditError) -> bool {
    matches!(e, audit::AuditError::Io(io) if io.kind() == std::io::ErrorKind::BrokenPipe)
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
                let (value, next) =
                    flag_value_str(args, index, || "--last requires a number".to_string())?;
                opts.last =
                    Some(value.parse::<usize>().map_err(|_| {
                        AppError::Usage(format!("invalid number for --last: {value}"))
                    })?);
                index = next;
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
    emit_config_warnings(&load_result);
    let mut stdout = std::io::stdout().lock();
    match audit::show_entries(&load_result.config.audit, &opts, &mut stdout) {
        Ok(()) => Ok(0),
        Err(audit::AuditError::FileNotFound) => {
            println!("omamori audit: no entries recorded yet");
            Ok(0)
        }
        Err(e) if is_broken_pipe(&e) => Ok(0),
        Err(e) => {
            eprintln!("omamori audit unknown: {e}");
            Ok(1)
        }
    }
}

fn run_audit_key(args: &[OsString]) -> Result<i32, AppError> {
    match args.get(3).and_then(|item| item.to_str()) {
        Some("rotate") => {
            guard_ai_config_modification("audit key rotate")?;

            let load_result = load_config(None)?;
            emit_config_warnings(&load_result);

            let Some(path) = audit::resolved_audit_path(&load_result.config.audit) else {
                eprintln!("omamori: cannot resolve audit path — HOME is unset, empty, or relative");
                eprintln!("  set audit.path explicitly in config.toml, or fix HOME, and retry");
                return Ok(1);
            };

            eprintln!("omamori: rotating audit HMAC key...");

            match audit::rotate_key(&path) {
                Ok(result) => {
                    eprintln!("omamori: key rotation complete.");
                    // Moved here from before the call (#477). Printed up front
                    // it also greeted every refusal, where no retired key file
                    // exists to verify anything against — and on the refusal
                    // #477 adds, `audit verify` cannot verify at all. Not "the
                    // retired key backup": the lines below tell the operator
                    // that copies of this file are not backups, and calling it
                    // one first invites the tidying-up they warn against.
                    eprintln!("  Old entries will still verify against the retired key file.");
                    eprintln!("  New key ID: {}", result.new_key_id);
                    eprintln!("  Retired key: {}", result.retired_path.display());
                    // #457: this line used to print a path and nothing else,
                    // which reads as an invitation to tidy it up or back it up
                    // — and both of those broke verification. Say what the file
                    // is for.
                    // One `eprintln!` with continuation strings, like the exit-2
                    // and exit-4 messages above — the terminal wraps it. The
                    // hand-wrapped version broke at ~70 columns in the middle
                    // of a clause on anything wider.
                    //
                    // The earlier wording ("copies under a different name are
                    // ignored") was false in the one case that matters: a copy
                    // named `audit-secret.<number>.retired` is not ignored, it
                    // is registered as that epoch. Copying `.1.retired` to
                    // `.2.retired` gives `key-2` the epoch-1 bytes while the
                    // active key moves to `key-3`, so entries already labelled
                    // `key-2` stop verifying — a permanent false tampering
                    // verdict produced by following the advice.
                    eprintln!(
                        "  Keep that file. Entries written before now can only be verified \
                         with it. If you want a spare, copy it somewhere outside this \
                         directory: a copy left beside it as audit-secret.<number>.retired \
                         is read as another key epoch, which relabels new entries and makes \
                         existing ones fail to verify."
                    );
                    eprintln!("  Run `omamori audit verify` to confirm chain integrity.");
                    append_key_rotation_event(
                        &load_result.config.audit,
                        &result.retired_key_id,
                        &result.new_key_id,
                    );
                    Ok(0)
                }
                Err(audit::AuditError::SecretUnavailable) => {
                    eprintln!("omamori: no audit secret found — nothing to rotate");
                    Ok(1)
                }
                // #477: its own arm, not the catch-all below. A refusal the
                // operator cannot act on is barely better than the silent
                // mislabelling it replaces, and `audit verify` established the
                // shape — say what was observed, then what to do about it.
                Err(audit::AuditError::KeyringUnusable(reason)) => {
                    eprintln!("omamori: key rotation refused — {reason}");
                    eprintln!(
                        "  Rotating without a complete listing of the key directory would \
                         retire the current key under the wrong epoch number, and entries \
                         signed by it would later read as tampered."
                    );
                    // "No key file was renamed or created" rather than
                    // "nothing was changed": `with_key_store_lock` may already
                    // have created `audit-secret.lock`, which holds no key
                    // material and is recreated on demand. The refusal test
                    // allows exactly that one file, and this line is what the
                    // operator reads instead of the test.
                    // "listable **and writable**": rotation renames and
                    // creates, so a directory made merely readable still fails
                    // here — measured at mode 0500, where both the rename and
                    // the create return EACCES.
                    eprintln!(
                        "  No key file was renamed or created. To fix: make that directory \
                         listable and writable again, then re-run."
                    );
                    Ok(1)
                }
                // #478: the one rotation failure that leaves the store changed.
                // Every refusal above this happens before the key directory is
                // touched; here the rename has already run, so `key rotation
                // failed` was being read as "nothing happened" in the single
                // case where something did. Which file moved is the fact the
                // operator needs, and the catch-all carried neither it nor the
                // fact that the store is now interrupted.
                Err(audit::AuditError::RotationInterrupted {
                    retired_path,
                    source,
                }) => {
                    for line in rotation_interrupted_lines(&retired_path, &source) {
                        eprintln!("{line}");
                    }
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

/// What `audit key rotate` prints when a rotation left the store mutated.
///
/// Split out so the wording is reachable from a test — the same move
/// `fold_key_dir_entries` makes for a per-entry listing error, and for the same
/// reason. Provoking this for real needs `rename` to succeed and
/// `create_secret` to fail in the same call on the same directory, and the two
/// need the same permissions: every state that stops the create stops the
/// rename first. What is left is a concurrent writer taking the name (a race no
/// test can schedule), `/dev/urandom` failing, ENOSPC and EMFILE. Taking the
/// values instead of producing them makes the branch reachable.
///
/// **It says nothing about what the store holds now.** The first draft said the
/// store "has retired keys and no active key" and that the next command "will
/// create one". The first is false when the failure was `AlreadyExists` — some
/// other writer put a file at that path, possibly a usable key — and the second
/// predicts a mint that can fail exactly the way this one just did. Both are
/// the shape #478 exists to remove, reintroduced inside the fix for it (Codex
/// Round 1). What this process observed is that it moved one file and did not
/// create another; the rest is left to `docs/FAQ.md`, which the operator reads
/// with the directory in front of them.
fn rotation_interrupted_lines(
    retired_path: &std::path::Path,
    source: &std::io::Error,
) -> Vec<String> {
    vec![
        // Literal em dash, like the sibling arms in this command. An escaped
        // codepoint is invisible to `check-invariants.sh`, which pins operator
        // text with `grep -F` on the bytes a developer sees on screen.
        format!("omamori: key rotation interrupted — {source}"),
        format!(
            "  The key being replaced has already moved to {}, and this rotation did not \
             create its replacement.",
            retired_path.display()
        ),
        "  What to do next turns on whether an audit-secret exists when you act: while none \
         does, moving that file back restores the state from before the rotation; once one \
         does, moving it back destroys the key that anything written in between was signed \
         with. See the audit chapter of omamori's FAQ."
            .to_string(),
    ]
}

/// The audit event a completed key rotation leaves behind (#457 A6).
///
/// Field values mirror `config_cmd`'s `build_config_mutation_event`, which
/// describes the other class of CLI-initiated state change omamori records.
///
/// `command` is deliberately not `_prune`: `retention.rs` identifies a prune
/// point by a `command`/`action`/`result` triple, and two of its three checks
/// look at `command` alone, so any other value keeps the two apart.
///
/// The retired key's path is **not** recorded — it would put the user's home
/// directory in the log for nothing, since the filename is derivable from the
/// epoch id this event already carries.
///
/// Not because paths are never logged in the clear: `parent_process` is one,
/// deliberately (`SECURITY.md`'s "Why `parent_process` is plaintext but
/// `cwd_hash` is hashed"). The distinction is what the plaintext buys — there,
/// naming the launching application is the whole point of the field; here it
/// duplicates an id that is already present.
fn build_key_rotation_event(retired_key_id: &str, new_key_id: &str) -> audit::AuditEvent {
    audit::AuditEvent {
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        provider: "cli".to_string(),
        command: "audit key rotate".to_string(),
        rule_id: None,
        action: "audit-key-rotate".to_string(),
        result: format!("rotated {retired_key_id} -> {new_key_id}"),
        target_count: 0,
        target_hash: String::new(),
        detection_layer: Some("key-rotation".to_string()),
        unwrap_chain: None,
        raw_input_hash: None,
        chain_version: None,
        seq: None,
        prev_hash: None,
        key_id: None,
        entry_hash: None,
        pid: None,
        ppid: None,
        parent_process: None,
        cwd_hash: None,
        wrapper_kind: None,
    }
}

/// Best-effort audit append for a completed key rotation (#457 A6), mirroring
/// `config_cmd`'s `append_config_mutation_event`: the key has already been
/// renamed by the time this runs, so nothing here rolls that back and nothing
/// here turns a completed rotation into a failure.
///
/// **Not a marker.** `verify` does not re-anchor at this event, infer an epoch
/// from it, or consult it in any key-resolution decision — it is an ordinary
/// entry, authenticated against the key its own `key_id` names like every
/// other line, and altering it is detected exactly as altering any other entry
/// is. What it is *not* is exempt from verification, and the claim is
/// deliberately no stronger than that. The event exists because PR1 removed
/// the only signal a rotation used to leave: before #457 rotating broke the
/// chain, and that breakage was how a rotation became visible at all.
///
/// Two states end in a warning instead of an entry, and both say "not
/// recorded" so the operator is never left to infer it from silence: auditing
/// being off, and — since #477 made rotation refuse an unlistable directory
/// upstream — a key store that degraded *during* the rotation. `SECURITY.md`'s
/// "Key rotation events" carries the reasoning for the second one, which is
/// where an operator would look for it.
fn append_key_rotation_event(
    audit_config: &audit::AuditConfig,
    retired_key_id: &str,
    new_key_id: &str,
) {
    let Some(logger) = audit::AuditLogger::from_config(audit_config) else {
        eprintln!(
            "omamori warning: auditing is disabled, so this key rotation was not recorded \
             in the audit log. The rotation itself completed."
        );
        return;
    };
    if !logger.secret_available() {
        // A backstop against a **race**, not a policy. #477 made rotation
        // refuse upstream when the directory cannot be listed, so what is left
        // here is the key store degrading between `rotate_key` returning and
        // this logger being built (the secret deleted, chmod'd, replaced with
        // a symlink; the directory made unlistable). Kept rather than deleted
        // because the asymmetry of the outcomes has not changed — a lost
        // record is recoverable, and an entry stamped with an id no keyring
        // can hold pins the store at cannot-verify permanently (`ADR-0007`).
        //
        // Says only that the entry could not be signed, not why: two causes
        // remain reachable and only one leaves the epoch unknown.
        // `load_signing_key` has already printed the specific condition;
        // naming a cause here would be guessing at which one.
        eprintln!(
            "omamori warning: this key rotation was not recorded in the audit log — the \
             entry could not be signed, and an unsigned one cannot be repaired later \
             (ADR-0007 forbids rewriting entries), so it would leave `omamori audit verify` \
             reporting cannot-verify permanently. The rotation itself completed; fix the \
             condition reported above."
        );
        return;
    }
    if let Err(e) = logger.append(build_key_rotation_event(retired_key_id, new_key_id)) {
        eprintln!("omamori warning: failed to audit-log key rotation: {e}");
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
    emit_config_warnings(&load_result);
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
            // #484: `None` carries one bit and three causes reach it, so this
            // line is wrong for one of them — an unlistable key directory,
            // where both the path and the secret are fine. The true cause is
            // printed above it by the keyring's anomaly report (#477), which
            // is why this was left rather than fixed here: correcting it means
            // widening a `pub use`d signature.
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

    /// #478. The rotation failure that leaves the store mutated is the one this
    /// arm exists for, and it is the one no end-to-end test can reach: `rename`
    /// and `create_secret` need the same directory permissions, so the states
    /// that stop the second stop the first. The wording is pinned here instead,
    /// against the two claims the first draft made and could not support.
    #[test]
    fn rotation_interrupted_message_states_only_what_the_rotation_did() {
        let lines = rotation_interrupted_lines(
            std::path::Path::new("/data/audit-secret.2.retired"),
            &std::io::Error::new(std::io::ErrorKind::AlreadyExists, "File exists"),
        );
        let text = lines.join("\n");

        // The headline. Without it a mutation of the one word that tells the
        // operator this failure is different from the four refusals above it
        // survives the suite (Phase 8 QA).
        assert!(
            text.contains("omamori: key rotation interrupted"),
            "the verdict has to name the state, not just the errno: {text}"
        );
        assert!(
            text.contains("/data/audit-secret.2.retired"),
            "which file moved is the fact the operator needs: {text}"
        );
        assert!(
            text.contains("did not create its replacement"),
            "and what this rotation did not do: {text}"
        );
        // `AlreadyExists` is the shape that makes the withdrawn claim false:
        // something is at that path, so "no active key" would be wrong, and it
        // may be a usable key another writer minted.
        assert!(
            !text.contains("no active key"),
            "the store's current contents are not something this process \
             observed: {text}"
        );
        assert!(
            !text.contains("will create one"),
            "predicting the next mint is the shape #478 removes; it can fail \
             exactly as this one did: {text}"
        );
        assert!(
            text.contains("File exists"),
            "the observed errno is quoted rather than summarised: {text}"
        );
        assert!(
            text.contains("omamori's FAQ"),
            "the procedure lives where the operator can follow it: {text}"
        );
    }

    /// #177 B3 (Codex Phase 6-B): the mixed-version parenthetical had zero
    /// test coverage of its own — the underlying `VerifyResult.v1_entries`/
    /// `v2_entries` fields were pinned elsewhere, but not this exact string
    /// format, and the one internal test that exercised both fields
    /// together used a symmetric 2+2 count that a swapped format argument
    /// (`v1`/`v2` labels transposed) would not have caught. Deliberately
    /// asymmetric here for that reason.
    #[test]
    fn format_verify_success_message_shows_mixed_version_breakdown() {
        let result = audit::VerifyResult {
            chain_entries: 3,
            v1_entries: 2,
            v2_entries: 1,
            ..Default::default()
        };
        assert_eq!(
            format_verify_success_message(&result),
            "omamori audit verify: 3 entries verified, chain intact. (2 v1 + 1 v2)"
        );
    }

    #[test]
    fn format_verify_success_message_omits_breakdown_for_single_version_log() {
        let result = audit::VerifyResult {
            chain_entries: 3,
            v1_entries: 3,
            v2_entries: 0,
            ..Default::default()
        };
        assert_eq!(
            format_verify_success_message(&result),
            "omamori audit verify: 3 entries verified, chain intact.",
            "an all-v1 (or all-v2) log must not show a redundant (N v1 + M v2) parenthetical"
        );

        let result = audit::VerifyResult {
            chain_entries: 3,
            v1_entries: 0,
            v2_entries: 3,
            ..Default::default()
        };
        assert_eq!(
            format_verify_success_message(&result),
            "omamori audit verify: 3 entries verified, chain intact."
        );
    }

    #[test]
    fn format_verify_success_message_combines_breakdown_with_other_suffixes() {
        let result = audit::VerifyResult {
            chain_entries: 5,
            v1_entries: 4,
            v2_entries: 1,
            legacy_entries: 2,
            torn_lines: 1,
            ..Default::default()
        };
        assert_eq!(
            format_verify_success_message(&result),
            "omamori audit verify: 5 entries verified, chain intact. (4 v1 + 1 v2) \
             (2 legacy skipped) (1 torn lines skipped)"
        );
    }

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

    fn audit_config(path: Option<std::path::PathBuf>) -> audit::AuditConfig {
        audit::AuditConfig {
            enabled: true,
            path,
            retention_days: 0,
            strict: false,
        }
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

    // --- Characterization tests (#392/#377): pin current flag-value error
    // wording (Shape B: missing-value and non-UTF8-value fold into the SAME
    // message) before the shared-helper migration. Returns before any
    // filesystem I/O, so no HOME/config setup needed. ---

    #[test]
    fn audit_show_last_missing_value_error_message() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--last".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--last requires a number");
    }

    #[test]
    fn audit_show_last_parse_failure_error_message() {
        // Distinct from the missing-value message above — preserved as-is
        // (this refactor's helper covers only the "get value or error"
        // half; parse failures stay at the call site).
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--last".into(),
            "not-a-number".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "invalid number for --last: not-a-number");
    }

    #[test]
    fn audit_show_rule_missing_value_error_message() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--rule".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--rule requires a value");
    }

    #[test]
    fn audit_show_provider_missing_value_error_message() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--provider".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--provider requires a value");
    }

    #[test]
    fn audit_show_action_missing_value_error_message() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--action".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--action requires a value");
    }

    #[test]
    fn audit_unknown_last_missing_value_error_message() {
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "unknown".into(),
            "--last".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--last requires a number");
    }

    #[test]
    #[cfg(unix)]
    fn audit_show_last_rejects_non_utf8_value_same_as_missing() {
        // Shape B: a non-UTF8 value must fold into the SAME message as a
        // missing value (not a different "invalid UTF-8" message) —
        // deliberate existing behavior, not something this refactor changes.
        let non_utf8 = crate::test_support::non_utf8_osstring();
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--last".into(),
            non_utf8,
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--last requires a number");
    }

    // Codex Phase 6-B adversarial review: only `audit show --last`'s fold
    // was pinned — `--rule`/`--provider`/`--action` and `audit unknown
    // --last` each independently wire the same shared `flag_value_str`
    // helper, so each needs its own pin.

    #[test]
    #[cfg(unix)]
    fn audit_show_rule_rejects_non_utf8_value_same_as_missing() {
        let non_utf8 = crate::test_support::non_utf8_osstring();
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--rule".into(),
            non_utf8,
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--rule requires a value");
    }

    #[test]
    #[cfg(unix)]
    fn audit_show_provider_rejects_non_utf8_value_same_as_missing() {
        let non_utf8 = crate::test_support::non_utf8_osstring();
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--provider".into(),
            non_utf8,
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--provider requires a value");
    }

    #[test]
    #[cfg(unix)]
    fn audit_show_action_rejects_non_utf8_value_same_as_missing() {
        let non_utf8 = crate::test_support::non_utf8_osstring();
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--action".into(),
            non_utf8,
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--action requires a value");
    }

    #[test]
    #[cfg(unix)]
    fn audit_unknown_last_rejects_non_utf8_value_same_as_missing() {
        let non_utf8 = crate::test_support::non_utf8_osstring();
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "unknown".into(),
            "--last".into(),
            non_utf8,
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "--last requires a number");
    }

    #[test]
    fn audit_show_last_adjacent_flag_greedy_value_consumption() {
        // Codex Phase 6-B: strengthens V-ADJ coverage for Shape B — `--last
        // --json` must consume the literal string "--json" as --last's
        // value (parsed and rejected by usize::parse), not recognize --json
        // as a flag.
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "audit".into(),
            "show".into(),
            "--last".into(),
            "--json".into(),
        ];
        let err = run_audit_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "invalid number for --last: --json");
    }
}
