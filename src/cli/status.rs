//! `omamori status [--refresh]` subcommand — health check all defense layers.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::AppError;
use crate::audit;
use crate::config::load_config;
use crate::installer::default_base_dir;
use crate::integrity;
use crate::util::usage_text;

pub(crate) fn run_status_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut base_dir = default_base_dir();
    let mut refresh = false;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--base-dir" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    AppError::Usage("status requires a path after --base-dir".to_string())
                })?;
                base_dir = PathBuf::from(value);
                index += 2;
            }
            "--refresh" => {
                refresh = true;
                index += 1;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown status flag: {arg}\n\n{}",
                    usage_text()
                )));
            }
        }
    }

    println!("\nomamori v{} — health check\n", env!("CARGO_PKG_VERSION"));

    let report = integrity::full_check(&base_dir);

    // Group items by category and print
    let categories = [
        "Shims",
        "Hooks",
        "Config",
        "Core Policy",
        "PATH",
        "Baseline",
    ];
    for cat in &categories {
        let cat_items: Vec<_> = report.items.iter().filter(|i| i.category == *cat).collect();
        if cat_items.is_empty() {
            continue;
        }
        println!("{}:", cat);
        for item in &cat_items {
            println!(
                "  {:<6} {:<36} {}",
                item.status.label(),
                item.name,
                item.detail
            );
        }
        println!();
    }

    // Detection engine summary (always displayed)
    let load_result = load_config(None).ok();
    let rule_count = load_result
        .as_ref()
        .map(|r| r.config.rules.iter().filter(|r| r.enabled).count())
        .unwrap_or(7);
    println!("Detection:");
    println!(
        "  {:<6} {:<36} {rule_count} rules active",
        "[ok]", "Layer 1 (PATH shim)"
    );
    println!(
        "  {:<6} {:<36} Unwrap stack active",
        "[ok]", "Layer 2 (hooks)"
    );
    println!(
        "  {:<6} {:<36} Claude Code + Codex CLI + Cursor",
        "[info]", "Layer 2 coverage"
    );
    {
        let audit_config = load_result
            .as_ref()
            .map(|r| &r.config.audit)
            .cloned()
            .unwrap_or_default();
        let summary = audit::audit_summary(&audit_config);
        if !summary.enabled {
            println!("  {:<6} {:<36} disabled", "[info]", "Layer 3 (audit)");
        } else if let Some(ref err) = summary.path_error {
            println!("  {:<6} {:<36} {err}", "[warn]", "Layer 3 (audit)");
        } else if !summary.secret_available {
            println!(
                "  {:<6} {:<36} HMAC secret missing",
                "[warn]", "Layer 3 (audit)"
            );
        } else if summary.entry_count == 0 {
            println!(
                "  {:<6} {:<36} enabled (log created on first event)",
                "[ok]", "Layer 3 (audit)"
            );
        } else {
            let retention = if summary.retention_days > 0 {
                format!(", retention: {}d", summary.retention_days)
            } else {
                String::new()
            };
            println!(
                "  {:<6} {:<36} {} entries{retention} (run 'omamori audit verify' to check chain)",
                "[ok]", "Layer 3 (audit)", summary.entry_count
            );
        }
    }
    println!();

    let exit_code = report.exit_code();
    match exit_code {
        0 => println!("All layers healthy."),
        2 => println!("Some warnings detected. Review above."),
        _ => println!("Issues detected. Run suggested commands to repair."),
    }

    // --refresh: regenerate baseline from current state
    if refresh {
        match integrity::generate_baseline(&base_dir) {
            Ok(baseline) => {
                integrity::write_baseline(&base_dir, &baseline)?;
                println!(
                    "\nBaseline refreshed (v{}, {}).",
                    baseline.version, baseline.generated_at
                );
            }
            Err(e) => {
                eprintln!("\nomamori: failed to refresh baseline: {e}");
            }
        }
    }

    println!();
    Ok(exit_code)
}
