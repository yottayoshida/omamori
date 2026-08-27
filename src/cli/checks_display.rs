//! Shared display utilities for doctor/status check output.
//!
//! Two things live here: the [`Out`] sink both commands write through (#544),
//! and the mapping from integrity `CheckItem.category` strings to doctor's
//! 4-section model. Status retains its own legacy formatter (since v0.10.0)
//! but shares the sink.

use std::io::Write;

use crate::integrity::CheckItem;

/// The stdout sink `doctor` and `status` render through (#544).
///
/// Neither command's verdict reads anything about the output — `doctor`'s
/// 0/1/2 comes from the `CheckItem` list, `--fix`'s from what the repairs did —
/// so a reader that walks away mid-report changes nothing about the answer.
/// Independence is the property, not ordering: `status` prints its banner
/// before it has run a single check. Writing
/// through `println!` made it change everything: the macro panics on `EPIPE`,
/// so `omamori doctor | head -3` exited 101, a value the documented three-code
/// contract does not contain.
///
/// **Write failures stop the output and are never propagated.** No `?`, no
/// `Result` in any caller's signature. That is deliberate rather than lazy:
/// `doctor --fix` interleaves printing with repairs, so a propagating write
/// error would abandon the repair half-done — trading #544 for something
/// worse. Dropping the text and finishing the work is the safe direction, and
/// the verdict the caller returns is unaffected either way.
pub struct Out<'a> {
    writer: &'a mut dyn Write,
    /// The kind of the first write failure, if any. `None` while healthy.
    stopped: Option<std::io::ErrorKind>,
}

impl<'a> Out<'a> {
    pub fn new(writer: &'a mut dyn Write) -> Self {
        Self {
            writer,
            stopped: None,
        }
    }

    /// One line, newline appended. A no-op once a write has failed.
    pub fn line(&mut self, args: std::fmt::Arguments<'_>) {
        self.emit(|w| writeln!(w, "{args}"));
    }

    /// A fragment with no newline, for the `print!(…)` / `println!(…)` pairs
    /// that build a line in two steps ("repairing…" then " [fixed]").
    pub fn part(&mut self, args: std::fmt::Arguments<'_>) {
        self.emit(|w| write!(w, "{args}"));
    }

    fn emit(&mut self, f: impl FnOnce(&mut dyn Write) -> std::io::Result<()>) {
        if self.stopped.is_some() {
            return;
        }
        if let Err(e) = f(self.writer) {
            self.stopped = Some(e.kind());
        }
    }

    /// Whether output stopped because the reader went away, as opposed to
    /// still being written or having failed for some other reason. Read by
    /// tests; production code deliberately does not branch on it — the point
    /// of this type is that the verdict does not depend on it.
    #[cfg(test)]
    pub fn reader_left(&self) -> bool {
        self.stopped == Some(std::io::ErrorKind::BrokenPipe)
    }
}

/// `println!` against an [`Out`]. Same formatting, no panic on a closed pipe.
macro_rules! out {
    ($o:expr) => { $o.line(format_args!("")) };
    ($o:expr, $($arg:tt)*) => { $o.line(format_args!($($arg)*)) };
}

/// `print!` against an [`Out`] — no trailing newline.
macro_rules! out_part {
    ($o:expr, $($arg:tt)*) => { $o.part(format_args!($($arg)*)) };
}

pub(crate) use {out, out_part};

/// Doctor's 4-section model (Layer 1 / Layer 2 / Integrity / Risk signals).
/// Risk signals come from `audit::report`, not from integrity checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DoctorSection {
    Layer1,
    Layer2,
    Integrity,
}

impl DoctorSection {
    pub fn heading(self) -> &'static str {
        match self {
            Self::Layer1 => "[Layer 1] PATH shims",
            Self::Layer2 => "[Layer 2] Hook defense",
            Self::Integrity => "[Integrity] Config & baseline",
        }
    }
}

/// Deterministic mapping from CheckItem.category to DoctorSection.
///
/// Categories are fixed strings from integrity.rs:
/// Shims, Hooks, Config, Core Policy, PATH, Baseline
pub fn map_category_to_section(category: &str) -> DoctorSection {
    match category {
        "Shims" | "PATH" => DoctorSection::Layer1,
        "Hooks" => DoctorSection::Layer2,
        "Config" | "Core Policy" | "Baseline" => DoctorSection::Integrity,
        _ => DoctorSection::Integrity,
    }
}

/// Group CheckItems by DoctorSection, preserving order within each group.
pub fn group_by_section(items: &[CheckItem]) -> [(DoctorSection, Vec<&CheckItem>); 3] {
    let mut layer1 = Vec::new();
    let mut layer2 = Vec::new();
    let mut integrity = Vec::new();

    for item in items {
        match map_category_to_section(item.category) {
            DoctorSection::Layer1 => layer1.push(item),
            DoctorSection::Layer2 => layer2.push(item),
            DoctorSection::Integrity => integrity.push(item),
        }
    }

    [
        (DoctorSection::Layer1, layer1),
        (DoctorSection::Layer2, layer2),
        (DoctorSection::Integrity, integrity),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::{CheckItem, CheckStatus};

    /// A stdout whose reader has already gone: every write fails with
    /// `BrokenPipe`, and it counts how many times it was asked.
    struct DeadPipe {
        writes: usize,
    }

    impl Write for DeadPipe {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The sink absorbs a departed reader and stops asking.
    ///
    /// Both halves matter. Absorbing is what keeps the caller's verdict — and,
    /// in `run_fix`, the rest of the repair — from being abandoned. Stopping is
    /// what keeps a long report from issuing one doomed syscall per line after
    /// the reader is already gone.
    #[test]
    fn out_absorbs_a_departed_reader_and_stops_writing() {
        let mut dead = DeadPipe { writes: 0 };
        {
            let o = &mut Out::new(&mut dead);
            out!(o, "first");
            out!(o, "second");
            out_part!(o, "third");
            out!(o);
            assert!(
                o.reader_left(),
                "the sink should record that the reader, not the disk, is the problem"
            );
        }
        assert_eq!(
            dead.writes, 1,
            "only the first line should reach a pipe nobody is reading"
        );
    }

    /// Occurrences of `println!`/`print!` that are not `eprintln!`/`eprint!`,
    /// in the part of `src` that ships (everything before its `#[cfg(test)]`).
    fn stdout_macro_sites(src: &str) -> Vec<&str> {
        let production = src
            .split_once("\n#[cfg(test)]")
            .map(|(head, _)| head)
            .unwrap_or(src);
        production
            .lines()
            .filter(|line| {
                ["println!", "print!"].iter().any(|m| {
                    line.match_indices(m).any(|(at, _)| {
                        // `eprintln!` contains `println!`; an identifier
                        // character in front means this is not a bare call.
                        at == 0
                            || !line[..at]
                                .chars()
                                .next_back()
                                .is_some_and(|c| c.is_alphanumeric() || c == '_')
                    })
                })
            })
            .collect()
    }

    /// #544: every stdout write in `doctor` and `status` goes through [`Out`].
    ///
    /// The behavioural tests in `tests/cli.rs` only see the branches a given
    /// fixture reaches — a `println!` left behind in a `--verbose` arm or a
    /// rare error path would keep panicking on a closed pipe and every one of
    /// them would still pass. This counts the whole file instead, so the
    /// conversion cannot be partial and cannot silently regress.
    #[test]
    fn doctor_and_status_never_write_to_stdout_outside_the_sink() {
        for (name, src) in [
            ("doctor.rs", include_str!("doctor.rs")),
            ("status.rs", include_str!("status.rs")),
        ] {
            let sites = stdout_macro_sites(src);
            assert!(
                sites.is_empty(),
                "{name}: {} line(s) still print outside `Out` — a closed pipe \
                 panics there and replaces the exit code (#544): {:#?}",
                sites.len(),
                sites
            );
        }
    }

    /// The detector above is not vacuous: it finds a bare call, and is not
    /// fooled by the `eprintln!` that every one of these files is full of.
    #[test]
    fn stdout_macro_sites_finds_bare_calls_and_skips_eprintln() {
        assert_eq!(
            stdout_macro_sites("fn f() { println!(\"x\"); }\n"),
            vec!["fn f() { println!(\"x\"); }"]
        );
        assert!(stdout_macro_sites("fn f() { eprintln!(\"x\"); }\n").is_empty());
        assert!(stdout_macro_sites("fn f() { eprint!(\"x\"); }\n").is_empty());
        assert!(
            stdout_macro_sites("fn f() { println!(\"x\"); }\n#[cfg(test)]\nprintln!();").len() == 1,
            "the test region is out of scope"
        );
    }

    #[test]
    fn test_category_mapping() {
        assert_eq!(map_category_to_section("Shims"), DoctorSection::Layer1);
        assert_eq!(map_category_to_section("PATH"), DoctorSection::Layer1);
        assert_eq!(map_category_to_section("Hooks"), DoctorSection::Layer2);
        assert_eq!(map_category_to_section("Config"), DoctorSection::Integrity);
        assert_eq!(
            map_category_to_section("Core Policy"),
            DoctorSection::Integrity
        );
        assert_eq!(
            map_category_to_section("Baseline"),
            DoctorSection::Integrity
        );
        assert_eq!(map_category_to_section("Unknown"), DoctorSection::Integrity);
    }

    #[test]
    fn test_group_by_section_preserves_order() {
        let items = vec![
            CheckItem {
                category: "Shims",
                name: "cp".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "Shims",
                name: "rm".to_string(),
                status: CheckStatus::Fail,
                detail: "missing".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "Shims",
                name: "mv".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
        ];
        let groups = group_by_section(&items);
        let names: Vec<&str> = groups[0].1.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["cp", "rm", "mv"]);
    }

    #[test]
    fn test_unknown_categories_land_in_integrity() {
        let items = vec![
            CheckItem {
                category: "FutureCategory",
                name: "a".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "",
                name: "b".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
        ];
        let groups = group_by_section(&items);
        assert!(groups[0].1.is_empty(), "Layer1 should be empty");
        assert!(groups[1].1.is_empty(), "Layer2 should be empty");
        assert_eq!(
            groups[2].1.len(),
            2,
            "both unknowns should land in Integrity"
        );
    }

    #[test]
    fn test_group_by_section() {
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
                name: "hook1".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
            CheckItem {
                category: "Config",
                name: "cfg".to_string(),
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
                remediation: None,
            },
        ];
        let groups = group_by_section(&items);
        assert_eq!(groups[0].0, DoctorSection::Layer1);
        assert_eq!(groups[0].1.len(), 1);
        assert_eq!(groups[1].0, DoctorSection::Layer2);
        assert_eq!(groups[1].1.len(), 1);
        assert_eq!(groups[2].0, DoctorSection::Integrity);
        assert_eq!(groups[2].1.len(), 1);
    }
}
