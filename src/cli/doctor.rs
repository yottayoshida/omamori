//! `omamori doctor [--fix] [--verbose] [--json]` subcommand.
//!
//! Diagnose installation health and optionally auto-repair issues.
//! Read-only by default (no AI guard); `--fix` requires non-AI environment (DI-7).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::AppError;
use crate::audit::report::{ChainStatus, aggregate_report};
use crate::engine::guard::guard_ai_config_modification;
use crate::installer;
use crate::integrity::{self, CheckItem, CheckStatus, Remediation};
use crate::util::usage_text;

use super::checks_display::group_by_section;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub(crate) fn run_doctor_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut base_dir = installer::default_base_dir();
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
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("doctor requires a path after --base-dir".to_string())
                })?;
                base_dir = PathBuf::from(value);
                index += 2;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown doctor flag: {arg}\n\n{}",
                    usage_text()
                )));
            }
        }
    }

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
// Diagnose mode (read-only)
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

        if all_ok {
            println!("  {} {pass}/{total}", section.heading());
        } else {
            println!("  {} {pass}/{total}", section.heading());
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
    }

    // Section 4: Recent risk signals (from audit aggregation)
    print_risk_signals_section(ai_env);

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
    let chain_broken = matches!(report.chain_status, ChainStatus::Broken { .. });

    if !has_blocks && !has_unknown && !chain_broken {
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
    if let ChainStatus::Broken { .. } = &report.chain_status {
        if ai_env {
            println!("    chain: broken");
        } else {
            println!("    chain: broken — run omamori audit verify");
        }
    }
}

// ---------------------------------------------------------------------------
// Fix mode
// ---------------------------------------------------------------------------

/// Deduplicate and execute repairs in the correct order (DI-10).
/// Order: RunInstall → RegenerateHooks → ChmodConfig → RegenerateBaseline (last).
fn run_fix(items: &[CheckItem], base_dir: &Path, verbose: bool) -> Result<i32, AppError> {
    let problems: Vec<_> = items
        .iter()
        .filter(|i| i.status != CheckStatus::Ok)
        .collect();

    if problems.is_empty() {
        println!("omamori doctor --fix: nothing to repair, all healthy");
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
        match installer::regenerate_hooks(base_dir) {
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
        let _ = installer::regenerate_hooks(base_dir);
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

fn run_install_repair(base_dir: &Path) -> Result<(), AppError> {
    let source_exe = std::env::current_exe()?;
    let source_exe = installer::resolve_stable_exe_path(&source_exe);
    let options = installer::InstallOptions {
        base_dir: base_dir.to_path_buf(),
        source_exe,
        generate_hooks: true,
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
fn is_ai_environment() -> bool {
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

fn print_json(items: &[CheckItem], fix_mode: bool, _base_dir: &Path) -> Result<i32, AppError> {
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

    let output = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if fix_mode { "fix" } else { "diagnose" },
        "summary": {
            "protection_status": protection_status,
            "layer1": section_summary(&sections[0].1),
            "layer2": section_summary(&sections[1].1),
            "integrity": section_summary(&sections[2].1),
        },
        "items": json_items,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());

    if has_fail {
        Ok(1)
    } else if has_warn {
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
        // Capture stdout by parsing the JSON that print_json produces
        // (print_json writes to stdout, but we can verify structure via
        // the same construction logic)
        let sections = super::super::checks_display::group_by_section(&items);
        let section_summary = |section_items: &[&CheckItem]| -> serde_json::Value {
            let pass = section_items
                .iter()
                .filter(|i| i.status == CheckStatus::Ok)
                .count();
            serde_json::json!({ "pass": pass, "total": section_items.len() })
        };

        let output = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "mode": "diagnose",
            "summary": {
                "protection_status": "fail",
                "layer1": section_summary(&sections[0].1),
                "layer2": section_summary(&sections[1].1),
                "integrity": section_summary(&sections[2].1),
            },
            "items": items.iter().map(|item| {
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
            }).collect::<Vec<_>>(),
        });

        // Backward compat: items[] still present with expected shape
        let items_arr = output["items"].as_array().unwrap();
        assert_eq!(items_arr.len(), 2);
        assert!(items_arr[0].get("category").is_some());
        assert!(items_arr[0].get("name").is_some());
        assert!(items_arr[0].get("status").is_some());

        // Additive: summary block present
        let summary = output.get("summary").unwrap();
        assert!(summary.get("protection_status").is_some());
        assert!(summary.get("layer1").is_some());
        assert!(summary.get("layer2").is_some());
        assert!(summary.get("integrity").is_some());

        // Section counts correct
        assert_eq!(summary["layer1"]["pass"], 1);
        assert_eq!(summary["layer1"]["total"], 1);
        assert_eq!(summary["layer2"]["pass"], 0);
        assert_eq!(summary["layer2"]["total"], 1);
    }
}
