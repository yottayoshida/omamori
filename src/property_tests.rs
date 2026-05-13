//! Cross-layer property test (v0.9.6 PR5, #146 P1-4).
//!
//! Pin the one-way implication: if Layer 1 (PATH shim) verdicts a
//! command invocation as Block / Trash / MoveTo, then Layer 2 (PreToolUse
//! hook) MUST block the wrapped command string. The reverse direction is
//! intentionally not pinned: Layer 2 may legitimately block strings whose
//! tokenized form Layer 1 allows (e.g. parse errors, env-var tampering on
//! non-shim verbs, structural pipe-to-shell, phase-1b token-level bypass).
//!
//! ## Why a crate-internal test, not `tests/`
//!
//! The property test must call a hermetic version of the hook check that
//! evaluates Phase 2 against an explicit rule slice instead of loading
//! config from disk, so that Layer 2 sees the same `Config::default()`
//! rule set as Layer 1. That helper
//! ([`crate::engine::hook::check_command_for_hook_with_rules`]) is
//! deliberately `pub(crate)` — re-exporting it would let downstream
//! integrations bypass user policy overrides and silently turn deny rules
//! into allows. Living in-tree under `#[cfg(test)] mod property_tests` is
//! the cleanest way to use it without widening the production API surface.
//!
//! ## Generator design (CWD-independent)
//!
//!   destructive_core × wrapper
//!
//!   destructive_core ∈ {rm-recursive, find-delete, chmod-777,
//!                       rsync-delete, git-push-force, git-clean-force}
//!     — covers every Block/Trash/MoveTo built-in rule emitted by
//!       `default_rules()`. The set of covered rule names is mirrored in
//!       the constant [`COVERED_DESTRUCTIVE_RULES`] and pinned by the unit
//!       test [`coverage_matches_default_rules_destructive_set`], so adding
//!       a new built-in destructive rule will fail the test until both the
//!       constant and the generator are updated.
//!
//!   wrapper ∈ {Direct,
//!              Sudo, Doas, Pkexec, EnvU,
//!              Timeout, Nice, Nohup, Command, Exec,
//!              BashC, PipeBash, PipeEnvS, SourceDevStdin}
//!     — every entry in `unwrap::TRANSPARENT_WRAPPERS` (sudo / env /
//!       timeout / nice / nohup / command / exec / doas / pkexec) is
//!       represented as a `Wrapper::*` variant, plus four shell-launcher
//!       variants closed in PR2 (`bash -c`, pipe-to-bash, env -S
//!       split-string, source /dev/stdin). The transparent-wrapper subset
//!       is pinned by [`wrapper_kinds_cover_transparent_wrappers_sot`] so
//!       a future addition to the SoT fails this test until the enum is
//!       extended.
//!
//! Path arguments are drawn from a fixed list of literal absolute paths so
//! the generator is independent of the test process's working directory
//! (see PR1 / `normalize_path_with_base` and the v0.9.6 PR5 design note in
//! `moonlit-sparking-meadow.md`).
//!
//! ## Properties (256 cases each)
//!
//!   1. [`cross_layer_layer1_destructive_implies_layer2_blocks`] — the core
//!      one-way implication.
//!   2. [`generator_emits_only_destructive_cores`] — sanity guard against
//!      `default_rules()` drifting away from generator coverage. If a
//!      built-in rule's `match_any` is tightened (e.g. `-fr` is removed
//!      from `rm-recursive-to-trash`), this property fires and forces the
//!      generator to be updated in lockstep.
//!
//! ## Companion unit test
//!
//!   [`coverage_matches_default_rules_destructive_set`] — explicit drift
//!     guard comparing [`COVERED_DESTRUCTIVE_RULES`] against the actual
//!     destructive rule names in `Config::default()`.

use crate::config::Config;
use crate::engine::hook::{HookCheckResult, check_command_for_hook_with_rules};
use crate::rules::{ActionKind, CommandInvocation, RuleConfig, match_rule};
use crate::unwrap::{BlockReason, ParseResult, parse_command_string};

use proptest::prelude::*;

// ----------------------------------------------------------------------
// Coverage manifest
// ----------------------------------------------------------------------

/// The destructive (Block / Trash / MoveTo) rule names from
/// `default_rules()` that the generator covers. Pinned by
/// [`coverage_matches_default_rules_destructive_set`] — adding or
/// renaming a destructive built-in rule must update both this list and the
/// matching generator branch in [`arb_destructive_core`].
const COVERED_DESTRUCTIVE_RULES: &[&str] = &[
    "rm-recursive-to-trash",
    "git-push-force-block",
    "git-clean-force-block",
    "chmod-777-block",
    "find-delete-block",
    "rsync-delete-block",
];

// ----------------------------------------------------------------------
// Layer judgment helpers
// ----------------------------------------------------------------------

/// Layer 1 destructive verdict: a protected-environment invocation of
/// `(program, args)` would be Blocked, sent to Trash, or MovedTo.
///
/// Mirrors the post-`match_rule` branch of `engine::shim::run_command`.
/// Context overrides (`engine::shim` Tier-1 path-based escalation) are
/// deliberately ignored: they are monotonic (Trash → Block on dangerous
/// paths), so the un-overridden rule action is the strongest one-way
/// implication antecedent.
///
/// `StashThenExec` (git reset --hard) and `LogOnly` are NOT considered
/// destructive — they execute the command after a safety net rather than
/// preventing it.
fn layer1_destructive(program: &str, args: &[String], rules: &[RuleConfig]) -> bool {
    let invocation = CommandInvocation::new(program.to_string(), args.to_vec());
    match match_rule(rules, &invocation) {
        Some(rule) => matches!(
            rule.action,
            ActionKind::Block | ActionKind::Trash | ActionKind::MoveTo
        ),
        None => false,
    }
}

/// Layer 2 blocking verdict against an explicit rule slice (hermetic; does
/// not read on-disk config). Returns true for any of the three blocking
/// variants of `check_command_for_hook_with_rules` (phase-1b token,
/// structural unwrap, rule match).
fn layer2_blocks(command: &str, rules: &[RuleConfig]) -> bool {
    matches!(
        check_command_for_hook_with_rules(command, rules),
        HookCheckResult::BlockMeta { .. }
            | HookCheckResult::BlockStructural { .. }
            | HookCheckResult::BlockRule { .. }
    )
}

// ----------------------------------------------------------------------
// Path generator (CWD-independent literals)
// ----------------------------------------------------------------------

/// Literal absolute paths. Constraints:
///   - No whitespace, no shell metacharacters → safe for unquoted
///     interpolation into `bash -c "..."`, `echo "..." | bash`, etc.
///   - Mix of /tmp / /etc / /var / /usr / /opt / /private / /Users to
///     exercise both safe-prefix and dangerous-prefix path classes (path
///     classification is layer-invariant in v0.9.6 — neither layer trims
///     prefixes — so the implication is pinned independent of path).
fn arb_path() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/tmp/foo".to_string()),
        Just("/tmp/dir-x".to_string()),
        Just("/tmp/scratch".to_string()),
        Just("/var/log/test.log".to_string()),
        Just("/etc/passwd".to_string()),
        Just("/etc/hosts".to_string()),
        Just("/usr/local/share/x".to_string()),
        Just("/opt/data".to_string()),
        Just("/private/tmp/y".to_string()),
        Just("/Users/test/work".to_string()),
    ]
}

// ----------------------------------------------------------------------
// Per-program destructive core generators
// ----------------------------------------------------------------------

/// `rm` with a flag combination that hits `rm-recursive-to-trash` rule
/// (`match_any: ["-r", "-rf", "-fr", "--recursive"]`). Includes the
/// reordered-flag forms `-r -f` / `-f -r`: `shell_words` preserves token
/// order, so these tokenize to two args while `-rf` / `-fr` tokenize to
/// one. The rule must match both shapes.
///
/// Note 1: `-Rf` / `-fR` / `-R` (uppercase) is intentionally excluded —
/// the built-in rule does not list `-R` in `match_any`, so those forms
/// are a known Layer 1 hole tracked separately. Including them would only
/// widen the antecedent-false (vacuous) part of the implication and
/// dilute coverage.
///
/// Note 2 (drift signal): `generator_emits_only_destructive_cores` fires
/// when `rm-recursive-to-trash`'s coverage genuinely collapses — for
/// example if BOTH `-r` AND `--recursive` are dropped from `match_any`,
/// or if the rule's `command` is renamed away from `rm`. Removing only
/// the multi-character bundles `-rf` / `-fr` is NOT enough to trip the
/// guard, because `rules::expand_short_flags` decomposes them into `-r`
/// and `-f` and the rule still matches via the surviving `-r`.
fn arb_rm_core() -> impl Strategy<Value = (String, Vec<String>)> {
    let flag_combo = prop_oneof![
        Just(vec!["-rf".to_string()]),
        Just(vec!["-fr".to_string()]),
        Just(vec!["-r".to_string()]),
        Just(vec!["-r".to_string(), "-f".to_string()]),
        Just(vec!["-f".to_string(), "-r".to_string()]),
        Just(vec!["--recursive".to_string()]),
    ];
    (flag_combo, arb_path()).prop_map(|(mut flags, path)| {
        flags.push(path);
        ("rm".to_string(), flags)
    })
}

/// `find <path> -delete` / `find <path> --delete` (find-delete-block rule).
fn arb_find_core() -> impl Strategy<Value = (String, Vec<String>)> {
    let delete_flag = prop_oneof![Just("-delete".to_string()), Just("--delete".to_string())];
    (arb_path(), delete_flag).prop_map(|(path, flag)| ("find".to_string(), vec![path, flag]))
}

/// `chmod 777 <path>` (chmod-777-block rule).
fn arb_chmod_core() -> impl Strategy<Value = (String, Vec<String>)> {
    arb_path().prop_map(|path| ("chmod".to_string(), vec!["777".to_string(), path]))
}

/// `rsync -av <src> <dst> --delete` (rsync-delete-block rule). Covers all
/// 8 destructive rsync flags listed in `default_rules()`.
fn arb_rsync_core() -> impl Strategy<Value = (String, Vec<String>)> {
    let delete_flag = prop_oneof![
        Just("--delete".to_string()),
        Just("--del".to_string()),
        Just("--delete-before".to_string()),
        Just("--delete-during".to_string()),
        Just("--delete-after".to_string()),
        Just("--delete-excluded".to_string()),
        Just("--delete-delay".to_string()),
        Just("--remove-source-files".to_string()),
    ];
    (arb_path(), arb_path(), delete_flag)
        .prop_map(|(src, dst, flag)| ("rsync".to_string(), vec!["-av".to_string(), src, dst, flag]))
}

/// `git push <remote> <branch> --force` / `-f` (git-push-force-block rule).
/// `match_all: ["push"]`, `match_any: ["--force", "-f"]`.
fn arb_git_push_force_core() -> impl Strategy<Value = (String, Vec<String>)> {
    let force_flag = prop_oneof![Just("--force".to_string()), Just("-f".to_string())];
    let remote = prop_oneof![Just("origin".to_string()), Just("upstream".to_string())];
    let branch = prop_oneof![Just("main".to_string()), Just("master".to_string())];
    (remote, branch, force_flag)
        .prop_map(|(r, b, flag)| ("git".to_string(), vec!["push".to_string(), r, b, flag]))
}

/// `git clean -f` / `git clean --force` (git-clean-force-block rule).
/// `match_all: ["clean"]`, `match_any: ["-f", "--force"]`. Force is required
/// because vanilla `git clean` is a no-op for safety.
fn arb_git_clean_force_core() -> impl Strategy<Value = (String, Vec<String>)> {
    let force_flag = prop_oneof![Just("-f".to_string()), Just("--force".to_string())];
    let extra_flag = prop_oneof![
        Just(Vec::<String>::new()),
        Just(vec!["-d".to_string()]),
        Just(vec!["-x".to_string()]),
    ];
    (force_flag, extra_flag).prop_map(|(force, extras)| {
        let mut args = vec!["clean".to_string(), force];
        args.extend(extras);
        ("git".to_string(), args)
    })
}

/// Union: any destructive core. Each variant has equal weight in the
/// uniform `prop_oneof!` distribution. The set must stay in lockstep with
/// [`COVERED_DESTRUCTIVE_RULES`] and the destructive subset of
/// `default_rules()` — see [`coverage_matches_default_rules_destructive_set`].
fn arb_destructive_core() -> impl Strategy<Value = (String, Vec<String>)> {
    prop_oneof![
        arb_rm_core(),
        arb_find_core(),
        arb_chmod_core(),
        arb_rsync_core(),
        arb_git_push_force_core(),
        arb_git_clean_force_core(),
    ]
}

// ----------------------------------------------------------------------
// Wrapper generators
// ----------------------------------------------------------------------

/// Wrapper variants. Each wrapper preserves the destructive intent:
/// the inner program is what eventually runs (or would run, in the
/// pipe-to-shell case where the launcher is structurally blocked).
///
/// The transparent-wrapper subset (`Sudo / Doas / Pkexec / EnvU /
/// Timeout / Nice / Nohup / Command / Exec`) covers every entry in
/// `unwrap::TRANSPARENT_WRAPPERS`; this is pinned by
/// [`wrapper_kinds_cover_transparent_wrappers_sot`] so SoT additions
/// fail-loud here.
#[derive(Debug, Clone, Copy)]
enum Wrapper {
    /// `<inner>` — no wrapper.
    Direct,
    /// `sudo <inner>` — privilege elevation wrapper.
    Sudo,
    /// `doas <inner>` — OpenBSD-derived sudo alternative (PR2 / #180).
    Doas,
    /// `pkexec <inner>` — PolicyKit elevation (PR2 / #180).
    Pkexec,
    /// `env -u SHLVL <inner>` — env wrapper unsetting a non-detector
    /// variable. SHLVL is intentional: detector vars (CLAUDECODE etc.)
    /// would short-circuit Phase 1B (HookCheckResult::BlockMeta) and mask
    /// the unwrap-stack peeling path being exercised here. Phase 1B
    /// detector-var coverage is tracked separately for v0.9.7 (#187).
    EnvU,
    /// `timeout 30 <inner>` — coreutils timeout wrapper. SoT entry.
    Timeout,
    /// `nice <inner>` — process-priority wrapper. SoT entry.
    Nice,
    /// `nohup <inner>` — disown-on-hangup wrapper. SoT entry.
    Nohup,
    /// `command <inner>` — POSIX `command` builtin / external. SoT entry.
    Command,
    /// `exec <inner>` — POSIX `exec` builtin (replaces shell). SoT entry.
    Exec,
    /// `bash -c "<inner>"` — shell launcher with `-c`.
    BashC,
    /// `echo "<inner>" | bash` — pipe-to-shell, classic v0.9.5 surface.
    PipeBash,
    /// `echo "<inner>" | env -S 'bash -e'` — split-string env launcher
    /// (PR2 / #178).
    PipeEnvS,
    /// `echo "<inner>" | bash -c 'source /dev/stdin'` — stdin source
    /// (PR2 / #179).
    SourceDevStdin,
}

/// Names of the transparent-wrapper subset of [`Wrapper`], in the
/// canonical SoT spelling. Pinned against `unwrap::TRANSPARENT_WRAPPERS`
/// by [`wrapper_kinds_cover_transparent_wrappers_sot`].
const WRAPPER_TRANSPARENT_NAMES: &[&str] = &[
    "sudo", "doas", "pkexec", "env", "timeout", "nice", "nohup", "command", "exec",
];

fn arb_wrapper() -> impl Strategy<Value = Wrapper> {
    prop_oneof![
        Just(Wrapper::Direct),
        Just(Wrapper::Sudo),
        Just(Wrapper::Doas),
        Just(Wrapper::Pkexec),
        Just(Wrapper::EnvU),
        Just(Wrapper::Timeout),
        Just(Wrapper::Nice),
        Just(Wrapper::Nohup),
        Just(Wrapper::Command),
        Just(Wrapper::Exec),
        Just(Wrapper::BashC),
        Just(Wrapper::PipeBash),
        Just(Wrapper::PipeEnvS),
        Just(Wrapper::SourceDevStdin),
    ]
}

/// Assemble the wrapped command string. Inner text is interpolated raw —
/// the path generator guarantees no whitespace, quotes, `$`, or backticks.
fn assemble_command(program: &str, args: &[String], wrapper: Wrapper) -> String {
    let inner = format!("{} {}", program, args.join(" "));
    match wrapper {
        Wrapper::Direct => inner,
        Wrapper::Sudo => format!("sudo {inner}"),
        Wrapper::Doas => format!("doas {inner}"),
        Wrapper::Pkexec => format!("pkexec {inner}"),
        Wrapper::EnvU => format!("env -u SHLVL {inner}"),
        Wrapper::Timeout => format!("timeout 30 {inner}"),
        Wrapper::Nice => format!("nice {inner}"),
        Wrapper::Nohup => format!("nohup {inner}"),
        Wrapper::Command => format!("command {inner}"),
        Wrapper::Exec => format!("exec {inner}"),
        Wrapper::BashC => format!("bash -c \"{inner}\""),
        Wrapper::PipeBash => format!("echo \"{inner}\" | bash"),
        Wrapper::PipeEnvS => format!("echo \"{inner}\" | env -S 'bash -e'"),
        Wrapper::SourceDevStdin => {
            format!("echo \"{inner}\" | bash -c 'source /dev/stdin'")
        }
    }
}

// ----------------------------------------------------------------------
// Combined case generator
// ----------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Case {
    program: String,
    args: Vec<String>,
    wrapper: Wrapper,
}

impl Case {
    fn command_string(&self) -> String {
        assemble_command(&self.program, &self.args, self.wrapper)
    }
}

fn arb_case() -> impl Strategy<Value = Case> {
    (arb_destructive_core(), arb_wrapper()).prop_map(|((program, args), wrapper)| Case {
        program,
        args,
        wrapper,
    })
}

// ----------------------------------------------------------------------
// Drift guards (deterministic unit tests, run always)
// ----------------------------------------------------------------------

/// Pin [`WRAPPER_TRANSPARENT_NAMES`] against `unwrap::TRANSPARENT_WRAPPERS`
/// (the single source of truth used by `unwrap_transparent` and
/// `segment_executes_shell_via_wrappers`). Adding a transparent wrapper
/// to the SoT without adding a matching `Wrapper::*` variant — and
/// updating `arb_wrapper`, `assemble_command`, and the doc — fires here.
///
/// This closes the prior PR5 review-round gap where the generator
/// silently covered only 4 of 9 SoT entries and the doc claimed full
/// SoT coverage.
#[test]
fn wrapper_kinds_cover_transparent_wrappers_sot() {
    let mut sot: Vec<&str> = crate::unwrap::TRANSPARENT_WRAPPERS.to_vec();
    sot.sort();

    let mut covered: Vec<&str> = WRAPPER_TRANSPARENT_NAMES.to_vec();
    covered.sort();

    assert_eq!(
        covered, sot,
        "Wrapper enum drifted from `unwrap::TRANSPARENT_WRAPPERS`.\n\
         Expected (WRAPPER_TRANSPARENT_NAMES): {covered:?}\n\
         Actual   (unwrap::TRANSPARENT_WRAPPERS): {sot:?}\n\
         Update WRAPPER_TRANSPARENT_NAMES, the Wrapper enum, arb_wrapper, \
         assemble_command, and the module-level doc when the SoT changes.",
    );
}

/// Pin [`COVERED_DESTRUCTIVE_RULES`] against the actual destructive subset
/// of `default_rules()`. Adding, removing, or renaming a destructive
/// built-in rule (Block / Trash / MoveTo) without updating both the
/// generator branch in [`arb_destructive_core`] and this constant fires
/// here, before any property test runs.
///
/// Excludes `command == "omamori"` rules (DI-13 Phase 2 backstop, v0.10.3+):
/// these protect omamori's own subcommands from AI-driven self-modification
/// and are not destructive shell commands. The proptest generator does not
/// emit `omamori uninstall` / `omamori config disable` etc., so coverage
/// expectation excludes them by design.
#[test]
fn coverage_matches_default_rules_destructive_set() {
    let config = Config::default();
    let mut actual: Vec<&str> = config
        .rules
        .iter()
        .filter(|r| {
            matches!(
                r.action,
                ActionKind::Block | ActionKind::Trash | ActionKind::MoveTo
            ) && r.command != "omamori"
        })
        .map(|r| r.name.as_str())
        .collect();
    actual.sort();

    let mut expected: Vec<&str> = COVERED_DESTRUCTIVE_RULES.to_vec();
    expected.sort();

    assert_eq!(
        actual, expected,
        "Generator coverage drifted from default_rules() destructive set.\n\
         Expected (COVERED_DESTRUCTIVE_RULES): {expected:?}\n\
         Actual   (default_rules destructive): {actual:?}\n\
         Update both COVERED_DESTRUCTIVE_RULES and arb_destructive_core when \
         a destructive built-in rule changes.",
    );
}

// ----------------------------------------------------------------------
// Wrapper-stack smoke (deterministic, depth ≥ 2)
// ----------------------------------------------------------------------

/// Single-wrapper variants exercise the first iteration of
/// `unwrap_transparent`'s while-loop (src/unwrap.rs:346) but never test
/// the recursive peel itself. A regression that breaks transparent-wrapper
/// chaining (e.g. an early-return after the first wrapper) would slip
/// past the 256-case property if every generated case has only one
/// wrapper.
///
/// This deterministic smoke covers three representative depth-2 / 3
/// stacks. Full exhaustive depth 0–3 coverage is deferred to v0.9.7
/// (#187, "stacked-unwrap-implication" property).
#[test]
fn wrapper_stack_smoke_pins_layer2_block() {
    let config = Config::default();

    // Each entry must produce a Layer 2 Block verdict (any variant) when
    // evaluated against the default rule set. Picked to span:
    //   1. transparent + transparent + destructive
    //   2. coreutils-only stack with no privilege-elevation arms
    //   3. transparent + shell-launcher (mixed peel + structural block)
    let stacks: &[&str] = &[
        "sudo env -u SHLVL rm -rf /tmp/foo",
        "timeout 30 nohup rm -rf /tmp/foo",
        "sudo env bash -c \"rm -rf /tmp/foo\"",
    ];

    for cmd in stacks {
        assert!(
            layer2_blocks(cmd, &config.rules),
            "Wrapper-stack smoke must Layer 2 Block: {cmd}",
        );
    }
}

// ----------------------------------------------------------------------
// Property tests
// ----------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Cross-layer one-way implication: Layer 1 destructive → Layer 2 blocks.
    ///
    /// Antecedent `layer1_destructive(program, args)` evaluates the inner
    /// core invocation against `default_rules()` — what the shim would see
    /// after the wrapper resolves. Consequent `layer2_blocks(cmd)` evaluates
    /// the full wrapped string through the hook pipeline against the same
    /// rule slice (hermetic; ambient user config has no effect).
    ///
    /// A failure means the hook would forward an AI-emitted command string
    /// that the shim would later block — i.e. a Layer 2 detection gap.
    #[test]
    fn cross_layer_layer1_destructive_implies_layer2_blocks(case in arb_case()) {
        let config = Config::default();
        let l1 = layer1_destructive(&case.program, &case.args, &config.rules);
        if l1 {
            let cmd = case.command_string();
            let l2 = layer2_blocks(&cmd, &config.rules);
            prop_assert!(
                l2,
                "Layer 1 destructive but Layer 2 allowed:\n  program: {}\n  args:    {:?}\n  wrapper: {:?}\n  cmd:     {}",
                case.program,
                case.args,
                case.wrapper,
                cmd,
            );
        }
    }

    /// Generator sanity guard: every emitted core IS destructive at Layer 1.
    ///
    /// This pins the generator against `default_rules()` drift. If a future
    /// PR removes a flag from a built-in rule's `match_any` (e.g. drops
    /// `-fr` from `rm-recursive-to-trash`), this property fires and forces
    /// the generator to be updated rather than silently emitting cores
    /// where the implication's antecedent is false (vacuous coverage).
    #[test]
    fn generator_emits_only_destructive_cores(case in arb_case()) {
        let config = Config::default();
        prop_assert!(
            layer1_destructive(&case.program, &case.args, &config.rules),
            "Generator emitted a non-destructive core:\n  program: {}\n  args:    {:?}\n  cmd:     {}",
            case.program,
            case.args,
            case.command_string(),
        );
    }

    /// Monotonicity: ObfuscatedExpansion does NOT flip Allow → Block on the
    /// FP regression corpus. Every command in `KNOWN_ALLOW_COMMANDS` must
    /// remain Allow after the v0.10.2 raw-scan addition.
    #[test]
    fn obfuscated_expansion_monotonicity(idx in 0..KNOWN_ALLOW_COMMANDS.len()) {
        let cmd = KNOWN_ALLOW_COMMANDS[idx];
        let result = parse_command_string(cmd);
        prop_assert!(
            !matches!(result, ParseResult::Block(BlockReason::ObfuscatedExpansion)),
            "FP regression: known-Allow command blocked as ObfuscatedExpansion:\n  cmd: {cmd}",
        );
    }

    /// Completeness pin: generated expansion patterns at verb position all
    /// trigger Block(ObfuscatedExpansion).
    #[test]
    fn obfuscated_expansion_completeness(case in arb_expansion_case()) {
        let result = parse_command_string(&case);
        prop_assert!(
            matches!(result, ParseResult::Block(BlockReason::ObfuscatedExpansion)),
            "Expansion at verb position was not blocked:\n  cmd: {case}",
        );
    }
}

// ----------------------------------------------------------------------
// ObfuscatedExpansion FP regression corpus (v0.10.2)
// ----------------------------------------------------------------------

/// Commands that MUST remain Allow. Drawn from the FP pin tests in
/// `src/unwrap.rs` and `tests/hook_integration.rs`. If a future change
/// to `raw_has_verb_obfuscation` causes any of these to flip to Block,
/// the monotonicity property fires.
const KNOWN_ALLOW_COMMANDS: &[&str] = &[
    "$HOME/bin/cargo build",
    "$EDITOR file.txt",
    "ls -la",
    "git status",
    "cargo test",
    "make -C build",
    "RUST_LOG=debug cargo test",
    "npm run build",
    "python3 script.py",
    "grep -rn pattern src/",
    "cat /etc/hosts",
    "echo hello world",
    "docker run -it ubuntu",
    "kubectl get pods",
    "terraform plan",
    "ssh user@host",
    "scp file.txt user@host:/tmp/",
    "curl -sL https://example.com",
    "wget https://example.com/file",
    "tar -xzf archive.tar.gz",
    "unzip archive.zip",
    "command -v rm",
    "sudo rm -rf /tmp/test",
    "env RUST_LOG=debug cargo test 2>&1 | grep FAIL",
];

// ----------------------------------------------------------------------
// ObfuscatedExpansion completeness generator (v0.10.2)
// ----------------------------------------------------------------------

/// Generates shell expansion patterns at verb position that must all be
/// detected by `raw_has_verb_obfuscation`. Covers ANSI-C quoting,
/// locale quoting, parameter expansion, brace expansion, mid-word
/// concat, and wrapper-prefixed variants.
fn arb_expansion_case() -> impl Strategy<Value = String> {
    let expansion_verb = prop_oneof![
        Just("$'rm' -rf /tmp/x"),
        Just("$\"rm\" -rf /tmp/x"),
        Just("${IFS}rm -rf /tmp/x"),
        Just("{rm,-rf,/tmp/x}"),
        Just("r$'m' -rf /tmp/x"),
        Just("r$\"m\" -rf /tmp/x"),
        Just("r${m} -rf /tmp/x"),
    ];

    let wrapper_prefix = prop_oneof![
        Just(""),
        Just("sudo "),
        Just("env "),
        Just("timeout 5 "),
        Just("nice "),
        Just("command "),
        Just("doas "),
    ];

    (wrapper_prefix, expansion_verb).prop_map(|(prefix, verb)| format!("{prefix}{verb}"))
}

/// Subshell-form patterns for Phase 2 builtin rule defense-in-depth testing.
/// Must include the `omamori` program because builtin rules
/// (`omamori-*-block`) target `program == "omamori"`.
const OMAMORI_SUBSHELL_PATTERNS: &[&str] = &[
    "omamori uninstall",
    "omamori init --force",
    "omamori override",
    "omamori doctor --fix",
    "omamori explain rm-recursive",
    "omamori config disable foo",
    "omamori config enable bar",
];

fn arb_omamori_subshell_pattern() -> impl Strategy<Value = &'static str> {
    prop::sample::select(OMAMORI_SUBSHELL_PATTERNS)
}

proptest! {
    /// Phase 2 defense-in-depth: omamori subcommand inside a
    /// `<shell> -c '...'` subshell MUST be BLOCKED via Phase 2 unwrap stack
    /// + PR1a builtin omamori-*-block rules. `config disable` without the
    /// `omamori` prefix is out of scope (program=config has no Phase 2
    /// builtin rule and is not a real omamori invocation).
    #[test]
    fn prop_subshell_inner_verb_blocked(
        shell in prop::sample::select(&["bash", "sh", "zsh"][..]),
        pattern in arb_omamori_subshell_pattern(),
    ) {
        let cmd = format!("{shell} -c '{pattern}'");
        let config = Config::default();
        let blocked = layer2_blocks(&cmd, &config.rules);
        prop_assert!(
            blocked,
            "omamori subcommand inside subshell must be BLOCKED: {cmd}"
        );
    }
}
