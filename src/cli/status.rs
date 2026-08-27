//! `omamori status [--refresh]` subcommand — health check all defense layers.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::AppError;
use crate::audit;
use crate::config::load_config;
use crate::installer::resolve_base_dir;
use crate::integrity;
use crate::util::{USAGE_HINT, flag_value};

use super::checks_display::{Out, out};

pub(crate) fn run_status_command(args: &[OsString]) -> Result<i32, AppError> {
    let mut stdout = std::io::stdout().lock();
    let o = &mut Out::new(&mut stdout);

    let mut base_dir: Option<PathBuf> = None;
    let mut refresh = false;
    let mut index = 2usize;

    while let Some(arg) = args.get(index).and_then(|item| item.to_str()) {
        match arg {
            "--base-dir" => {
                let (value, next) = flag_value(args, index, || {
                    "status requires a path after --base-dir".to_string()
                })?;
                base_dir = Some(PathBuf::from(value));
                index = next;
            }
            "--refresh" => {
                refresh = true;
                index += 1;
            }
            _ => {
                return Err(AppError::Usage(format!(
                    "unknown status flag: {arg}\n\n{}",
                    USAGE_HINT
                )));
            }
        }
    }

    let base_dir = resolve_base_dir(base_dir)?;

    out!(
        o,
        "\nomamori v{} — health check\n",
        env!("CARGO_PKG_VERSION")
    );

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
        out!(o, "{}:", cat);
        for item in &cat_items {
            out!(
                o,
                "  {:<6} {:<36} {}",
                item.status.label(),
                item.name,
                item.detail
            );
        }
        out!(o);
    }

    // Detection engine summary (always displayed)
    let load_result = load_config(None).ok();
    let rule_count = load_result
        .as_ref()
        .map(|r| r.config.rules.iter().filter(|r| r.enabled).count())
        .unwrap_or(7);
    out!(o, "Detection:");
    out!(
        o,
        "  {:<6} {:<36} {rule_count} rules active",
        "[ok]",
        "Layer 1 (PATH shim)"
    );
    out!(
        o,
        "  {:<6} {:<36} Unwrap stack active",
        "[ok]",
        "Layer 2 (hooks)"
    );
    out!(
        o,
        "  {:<6} {:<36} Claude Code + Codex CLI + Cursor",
        "[info]",
        "Layer 2 coverage"
    );
    {
        let audit_config = load_result
            .as_ref()
            .map(|r| &r.config.audit)
            .cloned()
            .unwrap_or_default();
        let summary = audit::audit_summary(&audit_config);
        if !summary.enabled {
            out!(o, "  {:<6} {:<36} disabled", "[info]", "Layer 3 (audit)");
        } else if let Some(ref err) = summary.path_error {
            out!(o, "  {:<6} {:<36} {err}", "[warn]", "Layer 3 (audit)");
        } else if let Some(reason) = &summary.unprotected_reason {
            // #471: this arm used to print `HMAC secret missing` for every
            // reason `read_secret` could fail, and never fired at all for the
            // state the writer actually refuses on — an unlistable key
            // directory, where the secret is present and readable. Both halves
            // were wrong in the same direction: at mode 0300 entries were being
            // recorded without HMAC protection while this line said `[ok]`.
            //
            // The reason comes from `audit_summary` rather than being assembled
            // here, so this surface cannot name a cause the writer would not.
            out!(
                o,
                "  {:<6} {:<36} {}",
                "[warn]",
                "Layer 3 (audit)",
                reason.summary()
            );
        } else if summary.entry_count == 0 {
            out!(
                o,
                "  {:<6} {:<36} enabled (log created on first event)",
                "[ok]",
                "Layer 3 (audit)"
            );
        } else {
            let retention = if summary.retention_days > 0 {
                format!(", retention: {}d", summary.retention_days)
            } else {
                String::new()
            };
            out!(
                o,
                "  {:<6} {:<36} {} entries{retention} (run 'omamori audit verify' to check chain)",
                "[ok]",
                "Layer 3 (audit)",
                summary.entry_count
            );
        }
    }

    // Break-glass status
    let bg_entries = crate::break_glass::read_active_entries();
    if !bg_entries.is_empty() {
        let names: Vec<String> = bg_entries
            .iter()
            .map(|e| {
                let r = e.remaining_secs().unwrap_or(0);
                format!(
                    "{} ({})",
                    e.rule_id,
                    crate::break_glass::format_remaining(r)
                )
            })
            .collect();
        out!(
            o,
            "  {:<6} {:<36} {} rule(s) bypassed: {}",
            "[warn]",
            "Break-glass",
            bg_entries.len(),
            names.join(", ")
        );
    }

    out!(o);

    let exit_code = report.exit_code();
    match exit_code {
        0 => out!(o, "All layers healthy."),
        2 => out!(o, "Some warnings detected. Review above."),
        _ => out!(o, "Issues detected. Run suggested commands to repair."),
    }

    // --refresh: regenerate baseline from current state
    if refresh {
        match integrity::generate_baseline(&base_dir) {
            Ok(baseline) => {
                integrity::write_baseline(&base_dir, &baseline)?;
                out!(
                    o,
                    "\nBaseline refreshed (v{}, {}).",
                    baseline.version,
                    baseline.generated_at
                );
            }
            Err(e) => {
                eprintln!("\nomamori: failed to refresh baseline: {e}");
            }
        }
    }

    out!(o);
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Characterization tests (#392/#377): pin current --base-dir error
    // wording and non-UTF8 handling. Returns before any filesystem I/O, so
    // no HOME/base-dir setup needed. `/simplify` Efficiency finding: these
    // were originally added as subprocess tests in tests/cli.rs (before
    // status.rs had a `mod tests`) — moved in-process here to match
    // install.rs/doctor.rs's sibling tests, since a process spawn is far
    // more expensive than an in-process call for logic that returns before
    // touching the filesystem.

    #[test]
    fn status_base_dir_missing_value_error_message() {
        let args: Vec<OsString> = vec!["omamori".into(), "status".into(), "--base-dir".into()];
        let err = run_status_command(&args).unwrap_err();
        assert_eq!(err.to_string(), "status requires a path after --base-dir");
    }

    #[test]
    #[cfg(unix)]
    fn status_base_dir_accepts_non_utf8_path() {
        let non_utf8 = crate::test_support::non_utf8_path_like();
        let args: Vec<OsString> = vec![
            "omamori".into(),
            "status".into(),
            "--base-dir".into(),
            non_utf8,
            "--bogus-next-flag".into(),
        ];
        let err = run_status_command(&args).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("unknown status flag: --bogus-next-flag"),
            "error: {err}"
        );
    }
}
