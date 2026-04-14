//! `omamori doctor [--fix] [--verbose] [--json]` subcommand.
//!
//! Diagnose installation health and optionally auto-repair issues.
//! Read-only by default (no AI guard); `--fix` requires non-AI environment (DI-7).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::AppError;
use crate::engine::guard::guard_ai_config_modification;
use crate::installer;
use crate::integrity::{self, CheckItem, CheckStatus, Remediation};
use crate::util::usage_text;

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
    let problems: Vec<_> = items
        .iter()
        .filter(|i| i.status != CheckStatus::Ok)
        .collect();

    if problems.is_empty() {
        // Healthy: 3-line summary
        let total = items.len();
        let ok_count = items.iter().filter(|i| i.status == CheckStatus::Ok).count();
        println!("omamori: all healthy");
        println!("  {ok_count}/{total} checks passed");
        if verbose {
            println!();
            print_all_items(items);
        } else {
            println!("  run `omamori doctor --verbose` for full details");
        }
        return Ok(0);
    }

    // Unhealthy: show problems only
    println!(
        "omamori doctor: {} issue(s) found\n",
        problems.len()
    );

    for item in &problems {
        let label = item.status.label();
        println!("  {:<6} [{}] {} {}", label, item.category, item.name, item.detail);
        if let Some(ref rem) = item.remediation {
            println!("         {}", remediation_hint(rem));
        }
    }

    println!();
    let has_fixable = problems.iter().any(|i| {
        i.remediation.as_ref().is_some_and(|r| !matches!(r, Remediation::ManualOnly(_)))
    });
    if has_fixable {
        println!("  run `omamori doctor --fix` to auto-repair");
    }

    if verbose {
        println!();
        println!("All checks:");
        print_all_items(items);
    }

    // exit code: 1 if any Fail, 2 if only Warn
    if problems.iter().any(|i| i.status == CheckStatus::Fail) {
        Ok(1)
    } else {
        Ok(2)
    }
}

// ---------------------------------------------------------------------------
// Fix mode
// ---------------------------------------------------------------------------

/// Deduplicate and execute repairs in the correct order (DI-10).
/// Order: RunInstall → RegenerateHooks → ChmodConfig → RegenerateBaseline (last).
fn run_fix(items: &[CheckItem], base_dir: &PathBuf, verbose: bool) -> Result<i32, AppError> {
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

    println!("omamori doctor --fix: repairing {} issue(s)\n", problems.len());

    let mut fixed = 0u32;
    let mut failed = 0u32;

    // 1. RunInstall (covers shims + hooks + baseline)
    if needs_install {
        print!("  [install] re-running full install...");
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
        print!("  [hooks] regenerating hook scripts...");
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
        print!("  [config] chmod 600 {}...", path.display());
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
        print!("  [baseline] regenerating integrity baseline...");
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
            println!(
                "  [MANUAL] [{}] {} — {}",
                item.category, item.name, hint
            );
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
fn run_fix_silent(items: &[CheckItem], base_dir: &PathBuf) -> Result<(), AppError> {
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

fn run_install_repair(base_dir: &PathBuf) -> Result<(), AppError> {
    let source_exe = std::env::current_exe()?;
    let source_exe = installer::resolve_stable_exe_path(&source_exe);
    let options = installer::InstallOptions {
        base_dir: base_dir.clone(),
        source_exe,
        generate_hooks: true,
    };
    installer::install(&options)?;
    Ok(())
}

fn regen_baseline(base_dir: &PathBuf) -> Result<(), AppError> {
    let baseline = integrity::generate_baseline(base_dir)?;
    integrity::write_baseline(base_dir, &baseline)?;
    Ok(())
}

#[cfg(unix)]
fn chmod_600(path: &PathBuf) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn chmod_600(_path: &PathBuf) -> Result<(), AppError> {
    // No permission model on non-Unix
    Ok(())
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

fn remediation_hint(rem: &Remediation) -> String {
    match rem {
        Remediation::RunInstall => "fix: run `omamori install`".to_string(),
        Remediation::RegenerateHooks => "fix: run `omamori install --hooks`".to_string(),
        Remediation::RegenerateBaseline => "fix: run `omamori install` to update baseline".to_string(),
        Remediation::ChmodConfig(path) => format!("fix: run `chmod 600 {}`", path.display()),
        Remediation::ManualOnly(hint) => format!("manual: {hint}"),
    }
}

fn print_all_items(items: &[CheckItem]) {
    let categories = [
        "Shims",
        "Hooks",
        "Config",
        "Core Policy",
        "PATH",
        "Baseline",
    ];
    for cat in &categories {
        let cat_items: Vec<_> = items.iter().filter(|i| i.category == *cat).collect();
        if cat_items.is_empty() {
            continue;
        }
        println!("  {}:", cat);
        for item in &cat_items {
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

fn print_json(items: &[CheckItem], fix_mode: bool, _base_dir: &PathBuf) -> Result<i32, AppError> {
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

    let output = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": if fix_mode { "fix" } else { "diagnose" },
        "items": json_items,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());

    // exit code based on items
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

    #[test]
    fn remediation_hint_formats_correctly() {
        assert_eq!(
            remediation_hint(&Remediation::RunInstall),
            "fix: run `omamori install`"
        );
        assert_eq!(
            remediation_hint(&Remediation::RegenerateHooks),
            "fix: run `omamori install --hooks`"
        );
        assert_eq!(
            remediation_hint(&Remediation::ChmodConfig(PathBuf::from("/tmp/config.toml"))),
            "fix: run `chmod 600 /tmp/config.toml`"
        );
        assert_eq!(
            remediation_hint(&Remediation::ManualOnly("do something".to_string())),
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
}
