//! `omamori doctor [--fix] [--verbose] [--json]` subcommand.
//!
//! Diagnose installation health and optionally auto-repair issues.
//! Writes nothing to disk by default (no AI guard); `--fix` requires
//! non-AI environment (DI-7). Note: since #349, the diagnose path can spawn
//! a short-lived probe subprocess (to verify a hook's embedded exe path
//! still satisfies the hook-check contract) — "read-only" here means no
//! filesystem mutation, not "no subprocess execution".

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::AppError;
use crate::audit::report::{ChainStatus, aggregate_report};
use crate::engine::guard::guard_ai_config_modification;
use crate::installer;
use crate::integrity::{self, CheckItem, CheckStatus, Remediation};
use crate::util::{USAGE_HINT, flag_value};

use time::OffsetDateTime;

use super::checks_display::{DoctorSection, group_by_section};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub(crate) fn run_doctor_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut base_dir: Option<PathBuf> = None;
    let mut fix = false;
    let mut verbose = false;
    let mut json = false;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--fix" => {
                fix = true;
                index += 1;
            }
            "--verbose" => {
                verbose = true;
                index += 1;
            }
            "--json" => {
                json = true;
                index += 1;
            }
            "--base-dir" => {
                let (value, next) = flag_value(args, index, || {
                    "doctor requires a path after --base-dir".to_string()
                })?;
                base_dir = Some(PathBuf::from(value));
                index = next;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown doctor flag: {arg}\n\n{USAGE_HINT}"
                )));
            }
        }
    }

    let base_dir = installer::resolve_base_dir(base_dir)?;

    // DI-7: --fix is blocked in AI environments
    if fix {
        guard_ai_config_modification("doctor --fix")?;
    }

    let report = integrity::full_check(&base_dir);

    if fix && json {
        // Execute repairs, then re-check and output JSON
        run_fix_silent(&report.items, &base_dir)?;
        let post_repair = integrity::full_check(&base_dir);
        return print_json(&post_repair.items, true, &base_dir);
    }

    if json {
        return print_json(&report.items, false, &base_dir);
    }

    if fix {
        run_fix(&report.items, &base_dir, verbose)
    } else {
        run_diagnose(&report.items, verbose)
    }
}

// ---------------------------------------------------------------------------
// Diagnose mode (no filesystem writes; may spawn a probe subprocess — #349)
// ---------------------------------------------------------------------------

fn run_diagnose(items: &[CheckItem], verbose: bool) -> Result<i32, AppError> {
    let has_fail = items.iter().any(|i| i.status == CheckStatus::Fail);
    let has_warn = items.iter().any(|i| i.status == CheckStatus::Warn);

    // Top-line: Protection status
    let status_word = if has_fail {
        "FAIL"
    } else if has_warn {
        "WARN"
    } else {
        "OK"
    };
    println!("Protection status: {status_word}");
    println!();

    let sections = group_by_section(items);
    let ai_env = is_ai_environment();

    for (section, section_items) in &sections {
        let pass = section_items
            .iter()
            .filter(|i| i.status == CheckStatus::Ok)
            .count();
        let total = section_items.len();
        let all_ok = pass == total;

        println!("  {} {pass}/{total}", section.heading());
        for annotate in section_annotations(*section) {
            annotate(ai_env);
        }
        if all_ok {
            continue;
        }
        for item in section_items {
            if item.status == CheckStatus::Ok {
                if verbose {
                    println!(
                        "    {:<6} {} {}",
                        item.status.label(),
                        item.name,
                        item.detail
                    );
                }
                continue;
            }
            println!(
                "    {:<6} {} {}",
                item.status.label(),
                item.name,
                item.detail
            );
            if let Some(ref rem) = item.remediation {
                println!("           {}", remediation_hint(rem, ai_env));
            }
        }
    }

    // Section 4: Recent risk signals (from audit aggregation)
    print_risk_signals_section(ai_env);

    // Section 5: Break-glass status
    print_break_glass_section(ai_env);

    // Section 6: Staging usage (#313)
    print_staging_section();

    println!();

    let problems: Vec<_> = items
        .iter()
        .filter(|i| i.status != CheckStatus::Ok)
        .collect();
    if !problems.is_empty() {
        let has_fixable = problems.iter().any(|i| {
            i.remediation
                .as_ref()
                .is_some_and(|r| !matches!(r, Remediation::ManualOnly(_)))
        });
        if has_fixable && !ai_env {
            println!("  run `omamori doctor --fix` to auto-repair");
        } else if has_fixable {
            println!("  issues detected — run doctor --fix directly in your terminal");
        }
    }

    if verbose && !items.is_empty() {
        println!();
        println!("All checks:");
        print_all_items(items);
    } else if problems.is_empty() {
        println!("  run `omamori doctor --verbose` for full details");
    }

    if has_fail {
        Ok(1)
    } else if has_warn {
        Ok(2)
    } else {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Section annotations (#310)
// ---------------------------------------------------------------------------

/// Which per-section informational lines `run_diagnose`'s loop prints after
/// each section heading. Replaces a single hardcoded
/// `if section == Layer1 { print_heartbeat_line() }` special case — a second
/// entry (e.g. a future Layer2 annotation) is a table addition here, not a
/// new `if` branch. Entries take `ai_env` because `print_heartbeat_line`'s
/// awaiting-state hint is gated by it (/code-review finding: the file-wide
/// convention this PR itself establishes — remediation_hint, risk-signals,
/// break-glass all gate human-oriented phrasing on `ai_env` — must apply
/// here too). Break-glass display stays a separate, standalone call (not a
/// table entry): it's a cross-cutting status independent of any one Layer's
/// check items, and folding it in here would interleave it between the
/// Layer 1 heading and Layer 1's own FAIL/WARN item list whenever Layer 1
/// has failures.
fn section_annotations(section: DoctorSection) -> &'static [fn(bool)] {
    match section {
        DoctorSection::Layer1 => &[print_heartbeat_line],
        DoctorSection::Layer2 | DoctorSection::Integrity => &[],
    }
}

/// Probes whether the resolved audit log path's parent directory accepts
/// writes, without touching `audit.jsonl` or its HMAC secret, and without
/// creating any directory (doctor's diagnose path writes nothing to disk
/// by default — see module doc). Best-effort: unresolvable
/// (`resolved_audit_path` → `None`, e.g. unusable `HOME`) or any I/O error
/// is reported as not writable rather than silently skipped — this is the
/// doctor-side complement to the sentinel-based stderr throttle in
/// `try_audit_append` (#359): the sentinel can itself be unwritable in the
/// same failure, so it can't be the only surface for this condition.
///
/// If the parent doesn't exist yet (fresh install, nothing has appended to
/// the audit log), probes the nearest existing ancestor instead — a
/// reasonable proxy, since a non-writable ancestor blocks creating the
/// parent too.
fn audit_path_is_writable(config: &crate::audit::AuditConfig) -> Option<bool> {
    let path = crate::audit::resolved_audit_path(config)?;
    let parent = path.parent()?;
    let probe_dir = std::iter::successors(Some(parent), |p| p.parent()).find(|p| p.exists())?;
    // Process ID alone is not unique enough: multiple threads within one
    // process (e.g. parallel `cargo test` runs) share it, and when
    // `probe_dir` resolves to a common ancestor (like the OS temp root),
    // concurrent calls collided on the same probe path — one thread's
    // `create_new` would spuriously fail with EEXIST against another
    // thread's in-flight probe. A per-process atomic counter closes this.
    static PROBE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = PROBE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let probe = probe_dir.join(format!(
        ".omamori-doctor-probe-{}-{seq}",
        std::process::id()
    ));
    Some(probe_write(&probe))
}

/// Attempts an atomic, symlink-safe write-then-cleanup at `probe_path`,
/// returning whether it succeeded. Split out from `audit_path_is_writable`
/// so tests can target a specific, pre-planted path directly instead of
/// needing to predict the counter-suffixed name that function generates.
fn probe_write(probe_path: &std::path::Path) -> bool {
    // `create_new` refuses to follow a pre-existing symlink/file at this
    // path (atomically fails instead), unlike a plain `write` which would
    // follow and truncate it.
    let writable = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(probe_path)
        .is_ok();
    let _ = std::fs::remove_file(probe_path);
    writable
}

/// Section 4: Recent risk signals from audit aggregation (last 30 days).
///
/// Uses `aggregate_report` from PR 1 to surface blocks and unknown-tool
/// fail-opens. All-zero state shows "quiet" indicator.
/// Best-effort: config/audit read failures → silent no-op.
fn print_risk_signals_section(ai_env: bool) {
    let Ok(load_result) = crate::config::load_config(None) else {
        return;
    };
    let report = aggregate_report(&load_result.config.audit, 30);

    let has_blocks = report.total_blocks > 0;
    let has_unknown = report.unknown_tool_fail_opens > 0;
    let chain_broken = matches!(
        report.chain_status,
        ChainStatus::Broken { .. } | ChainStatus::Truncated
    );
    let audit_unwritable = load_result.config.audit.enabled
        && matches!(
            audit_path_is_writable(&load_result.config.audit),
            Some(false) | None
        );

    if !has_blocks && !has_unknown && !chain_broken && !report.hwm_tampered && !audit_unwritable {
        println!("  [Risk signals] Last 30 days: quiet");
        return;
    }

    println!("  [Risk signals] Last 30 days");
    if has_blocks {
        println!("    {} block(s)", report.total_blocks);
    }
    if has_unknown {
        if ai_env {
            println!(
                "    {} unknown-tool fail-open(s) detected",
                report.unknown_tool_fail_opens
            );
        } else {
            println!(
                "    {} unknown-tool fail-open(s) — review: omamori audit unknown",
                report.unknown_tool_fail_opens
            );
        }
    }
    match &report.chain_status {
        ChainStatus::Broken { .. } => {
            if ai_env {
                println!("    chain: broken");
            } else {
                println!("    chain: broken — run omamori audit verify");
            }
        }
        ChainStatus::Truncated => {
            if ai_env {
                println!("    chain: truncated (entries may have been removed)");
            } else {
                println!("    chain: truncated — run omamori audit verify");
            }
        }
        _ => {}
    }
    if report.hwm_tampered {
        if ai_env {
            println!("    audit high-water-mark: unreadable/tampered");
        } else {
            println!(
                "    audit high-water-mark: unreadable or tampered — run omamori audit verify"
            );
        }
    }
    if audit_unwritable {
        if ai_env {
            println!(
                "    audit log: not writable — protection decisions are unaffected, but forensic trail is degraded"
            );
        } else {
            println!("    audit log: not writable — run omamori doctor --verbose to diagnose");
        }
    }
}

/// AI environments see only the bypass count, never `rule_id`/remaining-time
/// detail: `omamori doctor` (unlike `--fix`) is not blocked from AI agents,
/// so an unconditional detail dump would hand an AI agent an oracle for
/// exactly which protection rule has an active bypass window and how long it
/// has left — the same class of leak SEC-R5 already closes for remediation
/// hints.
fn print_break_glass_section(ai_env: bool) {
    let entries = crate::break_glass::read_active_entries();
    if entries.is_empty() {
        return;
    }
    println!();
    println!("  [Break-glass] {} active bypass(es)", entries.len());
    if ai_env {
        return;
    }
    for entry in &entries {
        let remaining = entry.remaining_secs().unwrap_or(0);
        println!(
            "    {}: {} remaining",
            entry.rule_id,
            crate::break_glass::format_remaining(remaining)
        );
    }
}

// ---------------------------------------------------------------------------
// Staging display (#313)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StagingInfo {
    file_count: u64,
    total_bytes: u64,
    oldest_days_ago: Option<i64>,
}

fn gather_staging_info() -> StagingInfo {
    let Some(dir) = crate::engine::hook::staging_dir() else {
        return StagingInfo::default();
    };

    let Ok(meta) = std::fs::symlink_metadata(&dir) else {
        return StagingInfo::default();
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return StagingInfo::default();
    }

    let Ok(entries) = std::fs::read_dir(&dir) else {
        return StagingInfo::default();
    };

    let now = std::time::SystemTime::now();
    let mut count = 0u64;
    let mut bytes = 0u64;
    let mut oldest_mtime: Option<std::time::SystemTime> = None;

    for entry in entries {
        let Ok(entry) = entry else { continue };
        let Ok(m) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !m.is_file() {
            continue;
        }
        let name = entry.file_name();
        if !crate::engine::hook::is_staging_filename(&name.to_string_lossy()) {
            continue;
        }
        count += 1;
        bytes += m.len();
        let mtime = m.modified().unwrap_or(now);
        oldest_mtime = Some(match oldest_mtime {
            Some(prev) if prev < mtime => prev,
            _ => mtime,
        });
    }

    let oldest_days_ago = oldest_mtime.and_then(|mt| {
        let secs = mt.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
        let mt_jd = OffsetDateTime::from_unix_timestamp(secs as i64)
            .ok()?
            .date()
            .to_julian_day();
        let today_jd = OffsetDateTime::now_utc().date().to_julian_day();
        Some(i64::from(today_jd - mt_jd))
    });

    StagingInfo {
        file_count: count,
        total_bytes: bytes,
        oldest_days_ago,
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} MB", bytes / (1024 * 1024))
    }
}

fn print_staging_section() {
    let info = gather_staging_info();

    if info.file_count == 0 {
        println!("  [Staging] empty");
        return;
    }

    let oldest_label = match info.oldest_days_ago {
        Some(0) => "today".to_string(),
        Some(1) => "1 day".to_string(),
        Some(n) => format!("{n} days"),
        None => "unknown".to_string(),
    };
    println!(
        "  [Staging] {} file(s), {}, oldest: {}",
        info.file_count,
        format_bytes(info.total_bytes),
        oldest_label,
    );

    let Ok(load_result) = crate::config::load_config(None) else {
        return;
    };
    let cfg = &load_result.config.structural;

    if cfg.max_files > 0 && info.file_count > u64::from(cfg.max_files) {
        println!("    WARN  file count exceeds max_files ({})", cfg.max_files);
    }
    if cfg.retention_days > 0
        && info
            .oldest_days_ago
            .is_some_and(|days| days > i64::from(cfg.retention_days) * 2)
    {
        println!(
            "    WARN  oldest file exceeds 2\u{00d7} retention_days ({})",
            cfg.retention_days
        );
    }
}

fn staging_json_summary() -> serde_json::Value {
    let info = gather_staging_info();

    let Ok(load_result) = crate::config::load_config(None) else {
        return serde_json::json!({
            "file_count": info.file_count,
            "total_bytes": info.total_bytes,
            "oldest_days_ago": info.oldest_days_ago,
            "status": "error",
            "retention_days": null,
            "max_files": null,
        });
    };
    let retention_days = load_result.config.structural.retention_days;
    let max_files = load_result.config.structural.max_files;

    let status = if info.file_count == 0 {
        "ok"
    } else {
        let count_exceeded = max_files > 0 && info.file_count > u64::from(max_files);
        let age_exceeded = retention_days > 0
            && info
                .oldest_days_ago
                .is_some_and(|d| d > i64::from(retention_days) * 2);
        if count_exceeded || age_exceeded {
            "warn"
        } else {
            "ok"
        }
    };

    serde_json::json!({
        "file_count": info.file_count,
        "total_bytes": info.total_bytes,
        "oldest_days_ago": info.oldest_days_ago,
        "status": status,
        "retention_days": retention_days,
        "max_files": max_files,
    })
}

// ---------------------------------------------------------------------------
// Heartbeat display
// ---------------------------------------------------------------------------

fn heartbeat_days_ago(path: &Path) -> Option<i64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let mtime = meta.modified().ok()?;
    let secs = mtime.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    let mtime_jd = OffsetDateTime::from_unix_timestamp(secs as i64)
        .ok()?
        .date()
        .to_julian_day();
    let today_jd = OffsetDateTime::now_utc().date().to_julian_day();
    Some(i64::from(today_jd - mtime_jd))
}

/// heartbeat is written at the very start of shim execution (Step 1a, before
/// any policy decision) — so any AI-tool-invoked guarded command, not just a
/// destructive one, updates it. The non-AI hint deliberately points at a
/// harmless command instead of the destructive examples earlier drafts used.
/// AI environments get a shorter form: telling an AI agent to "have your AI
/// tool run..." (referring to itself) is confusing rather than useful, and
/// every other doctor-output string this PR gates on `ai_env` follows the
/// same "run it yourself, directly in your terminal" phrasing (SEC-R5;
/// /code-review finding — this hint was the one exception).
fn print_heartbeat_awaiting_hint(ai_env: bool) {
    if ai_env {
        println!(
            "        hint: still awaiting first invocation \u{2014} run a harmless guarded \
             command, then re-run 'omamori doctor' directly in your terminal (not via AI)."
        );
    } else {
        println!(
            "        hint: open a new terminal tab, then have your AI tool run a harmless guarded \
             command (e.g. 'git status'). Re-run 'omamori doctor' \u{2014} this should switch to \
             \"last active: today\". Still awaiting? check that shims are on PATH."
        );
    }
}

/// Computes the awaiting-vs-active state once (rather than branching on
/// `heartbeat_path()` returning `None` and `heartbeat_days_ago()` returning
/// `None` as two separate duplicated cases — /code-review finding) and
/// prints accordingly.
fn print_heartbeat_line(ai_env: bool) {
    let days = crate::engine::shim::heartbeat_path().and_then(|p| heartbeat_days_ago(&p));
    match days {
        Some(days) if days < 0 => {
            println!("    WARN  last active: future timestamp \u{2014} clock skew detected");
        }
        Some(days) => {
            let label = match days {
                0 => "today".to_string(),
                1 => "yesterday".to_string(),
                n => format!("{n} days ago"),
            };
            if days <= 3 {
                println!("    last active: {label}");
            } else {
                println!(
                    "    WARN  last active: {label} \u{2014} shims may not be in PATH for AI tools"
                );
            }
        }
        None => {
            println!("    last active: awaiting first invocation");
            print_heartbeat_awaiting_hint(ai_env);
        }
    }
}

fn heartbeat_json_summary() -> serde_json::Value {
    let path = match crate::engine::shim::heartbeat_path() {
        Some(p) => p,
        None => {
            return serde_json::json!({
                "last_active_days_ago": null,
                "status": "awaiting_first_invocation",
            });
        }
    };
    match heartbeat_days_ago(&path) {
        Some(days) if days < 0 => {
            serde_json::json!({
                "last_active_days_ago": days,
                "status": "clock_skew",
            })
        }
        Some(days) => {
            let status = if days <= 3 { "ok" } else { "warn" };
            serde_json::json!({
                "last_active_days_ago": days,
                "status": status,
            })
        }
        None => {
            serde_json::json!({
                "last_active_days_ago": null,
                "status": "awaiting_first_invocation",
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Fix mode
// ---------------------------------------------------------------------------

/// #309: `--fix` previously stayed silent on heartbeat/break-glass — the
/// exact information someone running `--fix` because shims "aren't working"
/// most wants (structural checks can all read OK while AI tools still never
/// invoke the shim). Printed unconditionally by `run_fix`, including its
/// "nothing to repair" fast path: a stale heartbeat alongside an all-green
/// structural report is itself the diagnostic signal in that case.
///
/// `run_fix` is only reached after DI-7's guard already proved a non-AI
/// environment (`run_doctor_command`'s `--fix` arm), so `ai_env` is provably
/// `false` here today — `run_fix` computes it once (mirroring
/// `run_diagnose`'s own `let ai_env = is_ai_environment();`) and threads it
/// through rather than each caller re-deriving it, but still passes it (not
/// a literal `false`) so `print_break_glass_section`'s AI-oracle gate (T8)
/// holds on its own terms if the guard's placement ever changes.
fn print_fix_shim_activity_footer(ai_env: bool) {
    println!();
    println!("  [Shim activity]");
    print_heartbeat_line(ai_env);
    print_break_glass_section(ai_env);
}

/// Deduplicate and execute repairs in the correct order (DI-10).
/// Order: RunInstall → RegenerateHooks → ChmodConfig → RegenerateBaseline (last).
fn run_fix(items: &[CheckItem], base_dir: &Path, verbose: bool) -> Result<i32, AppError> {
    let ai_env = is_ai_environment();
    let problems: Vec<_> = items
        .iter()
        .filter(|i| i.status != CheckStatus::Ok)
        .collect();

    if problems.is_empty() {
        println!("omamori doctor --fix: nothing to repair, all healthy");
        print_fix_shim_activity_footer(ai_env);
        return Ok(0);
    }

    // Collect unique remediation actions
    let mut needs_install = false;
    let mut needs_regen_hooks = false;
    let mut needs_regen_baseline = false;
    let mut chmod_targets: BTreeSet<PathBuf> = BTreeSet::new();
    let mut manual_items: Vec<(&CheckItem, &str)> = Vec::new();

    for item in &problems {
        match item.remediation.as_ref() {
            Some(Remediation::RunInstall) => needs_install = true,
            Some(Remediation::RegenerateHooks) => needs_regen_hooks = true,
            Some(Remediation::RegenerateBaseline) => needs_regen_baseline = true,
            Some(Remediation::ChmodConfig(path)) => {
                chmod_targets.insert(path.clone());
            }
            Some(Remediation::ManualOnly(hint)) => {
                manual_items.push((item, hint));
            }
            None => {}
        }
    }

    // If RunInstall is needed, it covers hooks + shims + baseline
    if needs_install {
        needs_regen_hooks = false;
        needs_regen_baseline = false;
    }

    println!(
        "omamori doctor --fix: repairing {} issue(s)\n",
        problems.len()
    );

    let mut fixed = 0u32;
    let mut failed = 0u32;

    // 1. RunInstall (covers shims + hooks + baseline)
    if needs_install {
        print!("  [Layer 1] re-running full install...");
        match run_install_repair(base_dir) {
            Ok(()) => {
                println!(" [fixed]");
                fixed += 1;
            }
            Err(e) => {
                println!(" [FAILED] {e}");
                failed += 1;
            }
        }
    }

    // 2. RegenerateHooks (only if install wasn't needed)
    if needs_regen_hooks {
        print!("  [Layer 2] regenerating hook scripts...");
        let outcome = describe_regen_hooks_outcome(installer::regenerate_hooks_with_verifier(
            base_dir,
            installer::verify_hook_contract,
        ));
        println!("{}", outcome.message());
        if outcome.is_failure() {
            failed += 1;
        } else {
            fixed += 1;
        }
    }

    // 3. ChmodConfig
    for path in &chmod_targets {
        print!("  [Integrity] chmod 600 {}...", path.display());
        match chmod_600(path) {
            Ok(()) => {
                println!(" [fixed]");
                fixed += 1;
            }
            Err(e) => {
                println!(" [FAILED] {e}");
                failed += 1;
            }
        }
    }

    // 4. RegenerateBaseline (LAST per DI-10)
    if needs_regen_baseline {
        print!("  [Integrity] regenerating integrity baseline...");
        match regen_baseline(base_dir) {
            Ok(()) => {
                println!(" [fixed]");
                fixed += 1;
            }
            Err(e) => {
                println!(" [FAILED] {e}");
                failed += 1;
            }
        }
    }

    // 5. Manual items
    if !manual_items.is_empty() {
        println!();
        for (item, hint) in &manual_items {
            println!("  [MANUAL] [{}] {} — {}", item.category, item.name, hint);
        }
    }

    println!();
    if failed == 0 && manual_items.is_empty() {
        println!("  all issues fixed");
    } else if failed == 0 {
        println!(
            "  {fixed} fixed, {} require manual action",
            manual_items.len()
        );
    } else {
        println!(
            "  {fixed} fixed, {failed} failed, {} manual",
            manual_items.len()
        );
    }

    print_fix_shim_activity_footer(ai_env);

    if verbose {
        // Re-check after repair
        println!();
        println!("Post-repair check:");
        let recheck = integrity::full_check(base_dir);
        print_all_items(&recheck.items);
    }

    // exit code
    if failed > 0 {
        Ok(1)
    } else if !manual_items.is_empty() {
        Ok(2)
    } else {
        Ok(0)
    }
}

/// Execute repairs silently (for `--fix --json` mode).
/// Runs the same repair logic as `run_fix` but without stdout output.
fn run_fix_silent(items: &[CheckItem], base_dir: &Path) -> Result<(), AppError> {
    let problems: Vec<_> = items
        .iter()
        .filter(|i| i.status != CheckStatus::Ok)
        .collect();

    if problems.is_empty() {
        return Ok(());
    }

    let mut needs_install = false;
    let mut needs_regen_hooks = false;
    let mut needs_regen_baseline = false;
    let mut chmod_targets: BTreeSet<PathBuf> = BTreeSet::new();

    for item in &problems {
        match item.remediation.as_ref() {
            Some(Remediation::RunInstall) => needs_install = true,
            Some(Remediation::RegenerateHooks) => needs_regen_hooks = true,
            Some(Remediation::RegenerateBaseline) => needs_regen_baseline = true,
            Some(Remediation::ChmodConfig(path)) => {
                chmod_targets.insert(path.clone());
            }
            _ => {}
        }
    }

    if needs_install {
        needs_regen_hooks = false;
        needs_regen_baseline = false;
    }

    if needs_install {
        let _ = run_install_repair(base_dir);
    }
    if needs_regen_hooks {
        // #349 code review: use the same `_with_verifier` entry point as
        // `run_fix` (not the old `regenerate_hooks()` wrapper) for
        // consistency, even though the outcome is discarded here too — the
        // actual JSON exit code for this path comes from the fresh
        // `full_check()` re-scan the caller runs afterward, whose
        // `check_claude_settings_integration` independently re-verifies.
        let _ =
            installer::regenerate_hooks_with_verifier(base_dir, installer::verify_hook_contract);
    }
    for path in &chmod_targets {
        let _ = chmod_600(path);
    }
    if needs_regen_baseline {
        let _ = regen_baseline(base_dir);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Repair helpers
// ---------------------------------------------------------------------------

/// Outcome of `describe_regen_hooks_outcome`: the `[Layer 2]` print line
/// paired with whether it counts as a failure. An enum rather than a
/// `(String, bool)` tuple so the fixed/failure classification is enforced by
/// the match in `describe_regen_hooks_outcome` (and by `is_failure`'s own
/// exhaustive match below) rather than trusted convention at each call site
/// (/simplify review).
enum RegenHooksOutcome {
    Fixed(String),
    Failed(String),
}

impl RegenHooksOutcome {
    fn message(&self) -> &str {
        match self {
            RegenHooksOutcome::Fixed(m) | RegenHooksOutcome::Failed(m) => m,
        }
    }

    fn is_failure(&self) -> bool {
        matches!(self, RegenHooksOutcome::Failed(_))
    }
}

/// Formats `regenerate_hooks_with_verifier`'s result into the `[Layer 2]`
/// print line and whether it counts as a failure. Pure and separated from
/// `run_fix`'s orchestration specifically so every `HookKeptReason` variant's
/// message can be pinned directly, without needing to reproduce the
/// underlying condition (exe-resolution failure, contract-verification
/// failure, dev-build path) end-to-end — `run_fix` has no verifier/exe DI
/// seam of its own, so in-process tests can only ever drive whichever branch
/// the *test binary's own* `current_exe()` happens to hit (#354 test
/// adversarial review: this used to be `VerificationFailed` before #354, and
/// silently became `NonDeploymentPath` once the test binary's `target/debug`
/// path started tripping the new check first — the existing test's `code == 1`
/// assertion couldn't tell the difference, so `VerificationFailed`'s message
/// lost direct coverage without any test failing).
fn describe_regen_hooks_outcome(
    result: Result<installer::HookOutcome, std::io::Error>,
) -> RegenHooksOutcome {
    match result {
        Ok(installer::HookOutcome::Written) => RegenHooksOutcome::Fixed(" [fixed]".to_string()),
        Ok(installer::HookOutcome::KeptExisting(
            installer::HookKeptReason::VerificationFailed(status),
        )) => RegenHooksOutcome::Failed(format!(
            " [FAILED] resolved binary failed the hook-check contract ({status:?}); existing hook kept — try `omamori install --hooks`"
        )),
        Ok(installer::HookOutcome::KeptExisting(
            installer::HookKeptReason::ExeResolutionFailed,
        )) => RegenHooksOutcome::Failed(
            " [FAILED] could not resolve the current omamori binary; existing hook kept — try `omamori install --hooks`".to_string(),
        ),
        Ok(installer::HookOutcome::KeptExisting(
            installer::HookKeptReason::NonDeploymentPath,
        )) => RegenHooksOutcome::Failed(format!(
            " [FAILED] resolved binary {}; existing hook kept — rebuild from a stable path, or run `omamori install --hooks --source <path>` explicitly",
            installer::DEV_BUILD_PATH_DESCRIPTION
        )),
        Err(e) => RegenHooksOutcome::Failed(format!(" [FAILED] {e}")),
    }
}

fn run_install_repair(base_dir: &Path) -> Result<(), AppError> {
    let source_exe = std::env::current_exe()?;
    let source_exe = installer::resolve_stable_exe_path(&source_exe);
    let options = installer::InstallOptions {
        base_dir: base_dir.to_path_buf(),
        source: installer::SourceExe::Implicit(source_exe),
        generate_hooks: true,
        ..Default::default()
    };
    installer::install(&options)?;
    Ok(())
}

fn regen_baseline(base_dir: &Path) -> Result<(), AppError> {
    let baseline = integrity::generate_baseline(base_dir)?;
    integrity::write_baseline(base_dir, &baseline)?;
    Ok(())
}

#[cfg(unix)]
fn chmod_600(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn chmod_600(_path: &Path) -> Result<(), AppError> {
    // No permission model on non-Unix
    Ok(())
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// SEC-R5: in AI environments, suppress literal commands to prevent
/// AI agents from learning repair invocations as attack surface.
fn remediation_hint(rem: &Remediation, ai_env: bool) -> String {
    if ai_env {
        match rem {
            Remediation::ManualOnly(hint) => format!("manual: {hint}"),
            _ => "fix: run omamori doctor --fix directly in your terminal (not via AI)".to_string(),
        }
    } else {
        match rem {
            Remediation::RunInstall => "fix: run `omamori install`".to_string(),
            Remediation::RegenerateHooks => "fix: run `omamori install --hooks`".to_string(),
            Remediation::RegenerateBaseline => {
                "fix: run `omamori install` to update baseline".to_string()
            }
            Remediation::ChmodConfig(path) => format!("fix: run `chmod 600 {}`", path.display()),
            Remediation::ManualOnly(hint) => format!("manual: {hint}"),
        }
    }
}

/// Lightweight AI environment check reusing the detector infrastructure.
pub(crate) fn is_ai_environment() -> bool {
    let detectors = crate::config::default_detectors();
    let env_pairs: Vec<(String, String)> = std::env::vars().collect();
    let detection = crate::detector::evaluate_detectors(&detectors, &env_pairs);
    detection.protected
}

fn print_all_items(items: &[CheckItem]) {
    let sections = group_by_section(items);
    for (section, section_items) in &sections {
        if section_items.is_empty() {
            continue;
        }
        println!("  {}:", section.heading());
        for item in section_items {
            println!(
                "    {:<6} {:<36} {}",
                item.status.label(),
                item.name,
                item.detail
            );
        }
    }
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

fn build_json_output(items: &[CheckItem], fix_mode: bool) -> serde_json::Value {
    let json_items: Vec<serde_json::Value> = items
        .iter()
        .map(|item| {
            let mut obj = serde_json::json!({
                "category": item.category,
                "name": item.name,
                "status": item.status.label(),
                "detail": item.detail,
            });
            if let Some(ref rem) = item.remediation {
                obj["remediation"] = serde_json::json!(remediation_to_str(rem));
            }
            obj
        })
        .collect();

    let has_fail = items.iter().any(|i| i.status == CheckStatus::Fail);
    let has_warn = items.iter().any(|i| i.status == CheckStatus::Warn);
    let protection_status = if has_fail {
        "fail"
    } else if has_warn {
        "warn"
    } else {
        "ok"
    };

    let sections = group_by_section(items);
    let section_summary = |section_items: &[&CheckItem]| -> serde_json::Value {
        let pass = section_items
            .iter()
            .filter(|i| i.status == CheckStatus::Ok)
            .count();
        serde_json::json!({ "pass": pass, "total": section_items.len() })
    };

    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if fix_mode { "fix" } else { "diagnose" },
        "summary": {
            "protection_status": protection_status,
            "layer1": section_summary(&sections[0].1),
            "layer2": section_summary(&sections[1].1),
            "integrity": section_summary(&sections[2].1),
            "shim_activity": heartbeat_json_summary(),
            "staging": staging_json_summary(),
        },
        "items": json_items,
    })
}

fn print_json(items: &[CheckItem], fix_mode: bool, _base_dir: &Path) -> Result<i32, AppError> {
    let output = build_json_output(items, fix_mode);
    println!("{}", serde_json::to_string_pretty(&output).unwrap());

    if items.iter().any(|i| i.status == CheckStatus::Fail) {
        Ok(1)
    } else if items.iter().any(|i| i.status == CheckStatus::Warn) {
        Ok(2)
    } else {
        Ok(0)
    }
}

fn remediation_to_str(rem: &Remediation) -> &'static str {
    match rem {
        Remediation::RunInstall => "run_install",
        Remediation::RegenerateHooks => "regenerate_hooks",
        Remediation::RegenerateBaseline => "regenerate_baseline",
        Remediation::ChmodConfig(_) => "chmod_config",
        Remediation::ManualOnly(_) => "manual",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // hook_script_is_current was removed in favor of
    // `regenerate_hooks_with_verifier` returning `HookOutcome` directly
    // (#349 /simplify) — see `installer::tests::regenerate_hooks_creates_files`
    // and `regenerate_hooks_keeps_existing_hook_on_verification_failure` for
    // the equivalent Written/KeptExisting coverage.

    // --- section_annotations tests (#310) ---

    #[test]
    fn section_annotations_layer1_has_heartbeat_entry() {
        assert_eq!(section_annotations(DoctorSection::Layer1).len(), 1);
    }

    #[test]
    fn section_annotations_layer2_and_integrity_are_empty() {
        assert!(section_annotations(DoctorSection::Layer2).is_empty());
        assert!(section_annotations(DoctorSection::Integrity).is_empty());
    }

    #[test]
    fn section_annotations_entries_do_not_panic() {
        for section in [
            DoctorSection::Layer1,
            DoctorSection::Layer2,
            DoctorSection::Integrity,
        ] {
            for annotate in section_annotations(section) {
                annotate(false);
                annotate(true);
            }
        }
    }

    #[test]
    fn audit_path_writable_true_for_fresh_dir() {
        let dir = std::env::temp_dir().join(format!(
            "omamori-doctor-audit-writable-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        assert_eq!(audit_path_is_writable(&config), Some(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_path_writable_does_not_create_missing_parent() {
        // Doctor's diagnose path writes nothing to disk by default (module
        // doc) — probing writability for a not-yet-created audit dir must
        // not itself create it.
        let dir = std::env::temp_dir().join(format!(
            "omamori-doctor-audit-no-create-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        assert_eq!(audit_path_is_writable(&config), Some(true));
        assert!(
            !dir.exists(),
            "probing writability must not create the missing parent directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_write_false_when_path_is_symlink() {
        // Exercises `probe_write` directly (the atomic create-new-refuses-
        // symlink logic) rather than through `audit_path_is_writable`,
        // since that function's probe filename is now counter-suffixed
        // and not predictable enough to pre-plant a symlink at.
        let dir = std::env::temp_dir().join(format!(
            "omamori-doctor-probe-symlink-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let probe_path = dir.join("probe");
        let target = std::env::temp_dir().join(format!(
            "omamori-doctor-probe-symlink-target-{}",
            std::process::id()
        ));
        std::fs::write(&target, b"do not touch").unwrap();
        std::os::unix::fs::symlink(&target, &probe_path).unwrap();

        assert!(
            !probe_write(&probe_path),
            "create_new must refuse to follow a pre-existing symlink"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "do not touch",
            "symlink target must not be truncated by the probe"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&target);
    }

    #[test]
    fn audit_path_is_writable_no_race_under_concurrent_calls() {
        // Regression test for the TOCTOU race `PROBE_COUNTER` fixes:
        // multiple threads whose target audit-path parent doesn't exist
        // all fall back to probing the SAME existing ancestor directory
        // (`shared_ancestor` here stands in for what was, before this fix,
        // often the OS temp root when many tests' target dirs didn't
        // exist). Before the counter, concurrent `create_new` calls at the
        // same pid-only-named path could race and spuriously report
        // `Some(false)` (Codex test-adversarial review — the prior test
        // only checked single-threaded correctness, not the actual race).
        let shared_ancestor = std::env::temp_dir().join(format!(
            "omamori-doctor-race-ancestor-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&shared_ancestor);
        std::fs::create_dir_all(&shared_ancestor).unwrap();

        let handles: Vec<_> = (0..16)
            .map(|i| {
                let missing_parent = shared_ancestor.join(format!("missing-{i}"));
                std::thread::spawn(move || {
                    let config = crate::audit::AuditConfig {
                        enabled: true,
                        path: Some(missing_parent.join("audit.jsonl")),
                        retention_days: 0,
                        strict: false,
                    };
                    audit_path_is_writable(&config)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(
            results.iter().all(|r| *r == Some(true)),
            "all concurrent probes into the same writable ancestor must succeed, got: {results:?}"
        );

        let _ = std::fs::remove_dir_all(&shared_ancestor);
    }

    #[cfg(unix)]
    #[test]
    fn audit_path_writable_false_when_parent_readonly() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "omamori-doctor-audit-readonly-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let config = crate::audit::AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl")),
            retention_days: 0,
            strict: false,
        };
        assert_eq!(audit_path_is_writable(&config), Some(false));

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial_test::serial(home_env)]
    fn audit_path_writable_none_when_home_unusable_and_no_override() {
        let config = crate::audit::AuditConfig {
            enabled: true,
            path: None,
            retention_days: 0,
            strict: false,
        };
        let result = crate::test_support::with_home(Some(""), || audit_path_is_writable(&config));
        assert_eq!(result, None);
    }

    #[test]
    fn remediation_hint_non_ai() {
        assert_eq!(
            remediation_hint(&Remediation::RunInstall, false),
            "fix: run `omamori install`"
        );
        assert_eq!(
            remediation_hint(&Remediation::RegenerateHooks, false),
            "fix: run `omamori install --hooks`"
        );
        assert_eq!(
            remediation_hint(
                &Remediation::ChmodConfig(PathBuf::from("/tmp/config.toml")),
                false
            ),
            "fix: run `chmod 600 /tmp/config.toml`"
        );
        assert_eq!(
            remediation_hint(&Remediation::ManualOnly("do something".to_string()), false),
            "manual: do something"
        );
    }

    #[test]
    fn remediation_hint_ai_env_suppresses_literals() {
        let generic = "fix: run omamori doctor --fix directly in your terminal (not via AI)";
        assert_eq!(remediation_hint(&Remediation::RunInstall, true), generic);
        assert_eq!(
            remediation_hint(&Remediation::RegenerateHooks, true),
            generic
        );
        assert_eq!(
            remediation_hint(&Remediation::RegenerateBaseline, true),
            generic
        );
        assert_eq!(
            remediation_hint(&Remediation::ManualOnly("do something".to_string()), true),
            "manual: do something"
        );
    }

    #[test]
    fn remediation_to_str_covers_all_variants() {
        assert_eq!(remediation_to_str(&Remediation::RunInstall), "run_install");
        assert_eq!(
            remediation_to_str(&Remediation::RegenerateHooks),
            "regenerate_hooks"
        );
        assert_eq!(
            remediation_to_str(&Remediation::RegenerateBaseline),
            "regenerate_baseline"
        );
        assert_eq!(
            remediation_to_str(&Remediation::ChmodConfig(PathBuf::from("/tmp"))),
            "chmod_config"
        );
        assert_eq!(
            remediation_to_str(&Remediation::ManualOnly("x".to_string())),
            "manual"
        );
    }

    #[test]
    fn diagnose_healthy_returns_0() {
        let items = vec![CheckItem {
            category: "test",
            name: "ok_item".to_string(),
            status: CheckStatus::Ok,
            detail: "fine".to_string(),
            remediation: None,
        }];
        let code = run_diagnose(&items, false).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn diagnose_with_fail_returns_1() {
        let items = vec![CheckItem {
            category: "Shims",
            name: "rm".to_string(),
            status: CheckStatus::Fail,
            detail: "missing".to_string(),
            remediation: Some(Remediation::RunInstall),
        }];
        let code = run_diagnose(&items, false).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn diagnose_with_warn_only_returns_2() {
        let items = vec![CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Warn,
            detail: "after /usr/bin".to_string(),
            remediation: Some(Remediation::ManualOnly("fix PATH".to_string())),
        }];
        let code = run_diagnose(&items, false).unwrap();
        assert_eq!(code, 2);
    }

    #[test]
    fn fix_healthy_returns_0() {
        let items = vec![CheckItem {
            category: "test",
            name: "ok_item".to_string(),
            status: CheckStatus::Ok,
            detail: "fine".to_string(),
            remediation: None,
        }];
        let base_dir = PathBuf::from("/tmp/nonexistent");
        let code = run_fix(&items, &base_dir, false).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn fix_manual_only_returns_2() {
        let items = vec![CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Warn,
            detail: "after /usr/bin".to_string(),
            remediation: Some(Remediation::ManualOnly("fix PATH".to_string())),
        }];
        let base_dir = PathBuf::from("/tmp/nonexistent");
        let code = run_fix(&items, &base_dir, false).unwrap();
        assert_eq!(code, 2);
    }

    #[test]
    fn fix_regenerate_hooks_reports_failed_when_kept_existing() {
        // #349 QA gap: this is the exact re-derivation of Codex Round 1's P0
        // ("doctor --fix reports [fixed] for a silent no-op"). In a test
        // process, `current_exe()` resolves to the test harness binary —
        // itself always a `target/debug`/`target/release` path under
        // `cargo test` — so `regenerate_hooks_with_verifier` drives
        // `KeptExisting(NonDeploymentPath)` here (#354's dev-build check,
        // not the production contract verifier this test originally
        // exercised pre-#354; `run_fix` has no verifier/exe DI seam of its
        // own, so whichever `KeptExisting` reason the test binary's own path
        // happens to trip is the only one reachable this way — see
        // `describe_regen_hooks_outcome_*` below for direct per-variant
        // message coverage, including `VerificationFailed`, which this test
        // can no longer reach).
        let items = vec![CheckItem {
            category: "Hooks",
            name: "claude-pretooluse.sh".to_string(),
            status: CheckStatus::Fail,
            detail: "mismatch".to_string(),
            remediation: Some(Remediation::RegenerateHooks),
        }];
        let base_dir =
            std::env::temp_dir().join(format!("omamori-doctor-fix-regen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base_dir);

        let code = run_fix(&items, &base_dir, false).unwrap();
        assert_eq!(
            code, 1,
            "run_fix must report a failed exit code, not [fixed], when the hook is kept existing"
        );

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    // --- describe_regen_hooks_outcome (#354 test-adversarial follow-up) ---
    //
    // Direct, per-variant coverage of the [Layer 2] message/failure
    // classification — restores the `VerificationFailed` coverage that
    // `fix_regenerate_hooks_reports_failed_when_kept_existing` lost when
    // #354's dev-build check started intercepting the test binary's own
    // `current_exe()` before verification ever ran.

    #[test]
    fn describe_regen_hooks_outcome_written_is_fixed_not_failure() {
        let outcome = describe_regen_hooks_outcome(Ok(installer::HookOutcome::Written));
        assert_eq!(outcome.message(), " [fixed]");
        assert!(!outcome.is_failure());
    }

    #[test]
    fn describe_regen_hooks_outcome_verification_failed_is_failure() {
        let outcome = describe_regen_hooks_outcome(Ok(installer::HookOutcome::KeptExisting(
            installer::HookKeptReason::VerificationFailed(
                installer::HookContractStatus::ExitNonZero(1),
            ),
        )));
        assert!(outcome.is_failure());
        let message = outcome.message();
        assert!(
            message.contains("failed the hook-check contract"),
            "message: {message}"
        );
        assert!(message.contains("ExitNonZero(1)"), "message: {message}");
    }

    #[test]
    fn describe_regen_hooks_outcome_exe_resolution_failed_is_failure() {
        let outcome = describe_regen_hooks_outcome(Ok(installer::HookOutcome::KeptExisting(
            installer::HookKeptReason::ExeResolutionFailed,
        )));
        assert!(outcome.is_failure());
        assert!(
            outcome
                .message()
                .contains("could not resolve the current omamori binary"),
            "message: {}",
            outcome.message()
        );
    }

    #[test]
    fn describe_regen_hooks_outcome_non_deployment_path_is_failure() {
        let outcome = describe_regen_hooks_outcome(Ok(installer::HookOutcome::KeptExisting(
            installer::HookKeptReason::NonDeploymentPath,
        )));
        assert!(outcome.is_failure());
        assert!(
            outcome.message().contains("cargo build artifact"),
            "message: {}",
            outcome.message()
        );
    }

    #[test]
    fn describe_regen_hooks_outcome_err_is_failure() {
        let outcome = describe_regen_hooks_outcome(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        )));
        assert!(outcome.is_failure());
        assert!(
            outcome.message().contains("permission denied"),
            "message: {}",
            outcome.message()
        );
    }

    #[test]
    fn json_output_healthy_returns_0() {
        let items = vec![CheckItem {
            category: "test",
            name: "ok_item".to_string(),
            status: CheckStatus::Ok,
            detail: "fine".to_string(),
            remediation: None,
        }];
        let base_dir = PathBuf::from("/tmp");
        let code = print_json(&items, false, &base_dir).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn json_output_includes_remediation() {
        let items = vec![CheckItem {
            category: "Shims",
            name: "rm".to_string(),
            status: CheckStatus::Fail,
            detail: "missing".to_string(),
            remediation: Some(Remediation::RunInstall),
        }];
        let base_dir = PathBuf::from("/tmp");
        let code = print_json(&items, false, &base_dir).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn install_subsumes_hooks_and_baseline() {
        // When RunInstall is needed, RegenerateHooks and RegenerateBaseline
        // should be suppressed (install covers them all).
        let items = vec![
            CheckItem {
                category: "Shims",
                name: "rm".to_string(),
                status: CheckStatus::Fail,
                detail: "missing".to_string(),
                remediation: Some(Remediation::RunInstall),
            },
            CheckItem {
                category: "Hooks",
                name: "claude-pretooluse.sh".to_string(),
                status: CheckStatus::Fail,
                detail: "mismatch".to_string(),
                remediation: Some(Remediation::RegenerateHooks),
            },
            CheckItem {
                category: "Baseline",
                name: ".integrity.json".to_string(),
                status: CheckStatus::Warn,
                detail: "not found".to_string(),
                remediation: Some(Remediation::RegenerateBaseline),
            },
        ];

        // Verify dedup logic: collect unique actions
        let mut needs_install = false;
        let mut needs_regen_hooks = false;
        let mut needs_regen_baseline = false;
        for item in &items {
            match item.remediation.as_ref() {
                Some(Remediation::RunInstall) => needs_install = true,
                Some(Remediation::RegenerateHooks) => needs_regen_hooks = true,
                Some(Remediation::RegenerateBaseline) => needs_regen_baseline = true,
                _ => {}
            }
        }
        if needs_install {
            needs_regen_hooks = false;
            needs_regen_baseline = false;
        }
        assert!(needs_install);
        assert!(!needs_regen_hooks);
        assert!(!needs_regen_baseline);
    }

    #[test]
    fn json_summary_protection_status_warn_only() {
        let items = vec![CheckItem {
            category: "PATH",
            name: "shim order".to_string(),
            status: CheckStatus::Warn,
            detail: "after /usr/bin".to_string(),
            remediation: Some(Remediation::ManualOnly("fix PATH".to_string())),
        }];
        let output = build_json_output(&items, false);
        assert_eq!(output["summary"]["protection_status"], "warn");
    }

    #[test]
    fn json_summary_protection_status_all_ok() {
        let items = vec![
            CheckItem {
                category: "Shims",
                name: "rm".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "Hooks",
                name: "hook".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
        ];
        let output = build_json_output(&items, false);
        assert_eq!(output["summary"]["protection_status"], "ok");
    }

    #[test]
    fn remediation_hint_ai_env_suppresses_chmod() {
        let generic = "fix: run omamori doctor --fix directly in your terminal (not via AI)";
        assert_eq!(
            remediation_hint(
                &Remediation::ChmodConfig(PathBuf::from("/etc/omamori/config.toml")),
                true
            ),
            generic
        );
    }

    #[test]
    fn json_output_has_summary_and_items() {
        let items = vec![
            CheckItem {
                category: "Shims",
                name: "rm".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "Hooks",
                name: "hook".to_string(),
                status: CheckStatus::Fail,
                detail: "missing".to_string(),
                remediation: Some(Remediation::RegenerateHooks),
            },
        ];

        let output = build_json_output(&items, false);

        // Backward compat: items[] still present with expected shape
        let items_arr = output["items"].as_array().unwrap();
        assert_eq!(items_arr.len(), 2);
        assert!(items_arr[0].get("category").is_some());
        assert!(items_arr[0].get("name").is_some());
        assert!(items_arr[0].get("status").is_some());
        assert_eq!(items_arr[1]["remediation"], "regenerate_hooks");

        // Additive: summary block present
        let summary = output.get("summary").unwrap();
        assert_eq!(summary["protection_status"], "fail");
        assert!(summary.get("layer1").is_some());
        assert!(summary.get("layer2").is_some());
        assert!(summary.get("integrity").is_some());

        // Section counts correct
        assert_eq!(summary["layer1"]["pass"], 1);
        assert_eq!(summary["layer1"]["total"], 1);
        assert_eq!(summary["layer2"]["pass"], 0);
        assert_eq!(summary["layer2"]["total"], 1);

        // Top-level keys: version, mode, summary, items
        assert!(output.get("version").is_some());
        assert_eq!(output["mode"], "diagnose");
    }

    // --- Heartbeat display ---

    #[test]
    fn heartbeat_days_ago_missing_file() {
        let path = PathBuf::from("/tmp/omamori-hb-nonexistent-file");
        assert_eq!(heartbeat_days_ago(&path), None);
    }

    #[test]
    fn heartbeat_days_ago_today() {
        let dir = PathBuf::from(format!(
            "/tmp/omamori-hb-doctor-today-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("heartbeat");
        std::fs::write(&path, "test").unwrap();

        let days = heartbeat_days_ago(&path);
        assert_eq!(days, Some(0));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_days_ago_past() {
        let dir = PathBuf::from(format!(
            "/tmp/omamori-hb-doctor-past-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("heartbeat");
        std::fs::write(&path, "test").unwrap();

        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(86400 * 5);
        let times = std::fs::FileTimes::new().set_modified(past);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(times).unwrap();
        drop(file);

        let days = heartbeat_days_ago(&path).unwrap();
        assert!((4..=6).contains(&days), "expected ~5 days ago, got {days}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_threshold_boundary() {
        let dir = PathBuf::from(format!(
            "/tmp/omamori-hb-doctor-boundary-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("heartbeat");

        // 3 days ago → ok (last day before warn)
        std::fs::write(&path, "test").unwrap();
        let three_days = std::time::SystemTime::now() - std::time::Duration::from_secs(86400 * 3);
        let times = std::fs::FileTimes::new().set_modified(three_days);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(times).unwrap();
        drop(file);

        let days_3 = heartbeat_days_ago(&path).unwrap();
        assert!(days_3 <= 3, "3 days ago should be <= 3, got {days_3}");

        // 4 days ago → warn (first day of warn)
        let four_days =
            std::time::SystemTime::now() - std::time::Duration::from_secs(86400 * 4 + 3600);
        let times = std::fs::FileTimes::new().set_modified(four_days);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(times).unwrap();
        drop(file);

        let days_4 = heartbeat_days_ago(&path).unwrap();
        assert!(days_4 >= 4, "4+ days ago should be >= 4, got {days_4}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn heartbeat_days_ago_rejects_symlink() {
        let dir = PathBuf::from(format!("/tmp/omamori-hb-doctor-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, "x").unwrap();
        let path = dir.join("heartbeat");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert_eq!(heartbeat_days_ago(&path), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn heartbeat_days_ago_skips_directory() {
        let dir = PathBuf::from(format!("/tmp/omamori-hb-doctor-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("heartbeat");
        std::fs::create_dir_all(&path).unwrap();

        assert_eq!(heartbeat_days_ago(&path), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_output_includes_shim_activity() {
        let items = vec![CheckItem {
            category: "Shims",
            name: "rm".to_string(),
            status: CheckStatus::Ok,
            detail: "ok".to_string(),
            remediation: None,
        }];
        let output = build_json_output(&items, false);
        let activity = output["summary"].get("shim_activity");
        assert!(activity.is_some(), "shim_activity must be in summary");
        let activity = activity.unwrap();
        assert!(
            activity.get("status").is_some(),
            "shim_activity must have status"
        );
        assert!(
            activity.get("last_active_days_ago").is_some(),
            "shim_activity must have last_active_days_ago"
        );
        let status = activity["status"].as_str().unwrap();
        assert!(
            ["ok", "warn", "clock_skew", "awaiting_first_invocation"].contains(&status),
            "unexpected status: {status}"
        );
    }

    // --- Staging section (#313) ---

    #[test]
    fn json_output_includes_staging() {
        let items = vec![CheckItem {
            category: "Shims",
            name: "rm".to_string(),
            status: CheckStatus::Ok,
            detail: "ok".to_string(),
            remediation: None,
        }];
        let output = build_json_output(&items, false);
        let staging = output["summary"].get("staging");
        assert!(staging.is_some(), "staging must be in summary");
        let staging = staging.unwrap();
        assert!(staging.get("file_count").is_some());
        assert!(staging.get("total_bytes").is_some());
        assert!(staging.get("oldest_days_ago").is_some());
        assert!(staging.get("status").is_some());
        assert!(staging.get("retention_days").is_some());
        assert!(staging.get("max_files").is_some());
        let status = staging["status"].as_str().unwrap();
        assert!(
            ["ok", "warn"].contains(&status),
            "unexpected staging status: {status}"
        );
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1 KB");
        assert_eq!(format_bytes(49152), "48 KB");
        assert_eq!(format_bytes(1048576), "1 MB");
        assert_eq!(format_bytes(5242880), "5 MB");
    }

    #[test]
    fn gather_staging_info_does_not_panic() {
        // May or may not have files depending on system state, but should not panic
        let _info = gather_staging_info();
    }

    // --- Characterization tests (#392/#377): pin current --base-dir
    // error wording before the shared-helper migration. Returns before any
    // filesystem I/O, so no HOME/base-dir setup needed. ---

    #[test]
    fn doctor_base_dir_missing_value_error_message() {
        let args = vec![
            OsString::from("omamori"),
            OsString::from("doctor"),
            OsString::from("--base-dir"),
        ];
        let err = run_doctor_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "doctor requires a path after --base-dir");
    }

    #[test]
    #[cfg(unix)]
    fn doctor_base_dir_accepts_non_utf8_path() {
        let non_utf8 = crate::test_support::non_utf8_path_like();
        let args = vec![
            OsString::from("omamori"),
            OsString::from("doctor"),
            OsString::from("--base-dir"),
            non_utf8,
            OsString::from("--bogus-next-flag"),
        ];
        // Non-UTF8 --base-dir value accepted (not rejected); the loop moves
        // on to the next token, which is an unrecognized flag.
        let err = run_doctor_command(&args).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("unknown doctor flag: --bogus-next-flag"),
            "error: {err}"
        );
    }
}
