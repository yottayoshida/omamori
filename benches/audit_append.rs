//! Audit ledger append micro-benchmark.
//!
//! Measures `AuditLogger::append` end-to-end (flock acquire +
//! `read_chain_state` tail seek + HMAC entry hash + JSON serialize +
//! fs append). The ledger lives under
//! `$HOME/.cache/omamori-bench-audit-<pid>/` for the lifetime of the
//! bench process. macOS `temp_dir()` is avoided because its sandbox
//! blocked-prefix interacts with omamori's own protections; `$HOME`
//! is the safe location per workspace convention.
//!
//! Each iteration appends one fresh event (cloned from a template)
//! to a long-lived logger so flock contention + chain integrity
//! reflect realistic steady-state operation. The ledger grows
//! across iterations; `read_chain_state` is a tail seek so per-append
//! latency is expected to stay flat.

use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use omamori::actions::ActionOutcome;
use omamori::audit::{AuditConfig, AuditEvent, AuditLogger};
use omamori::rules::{ActionKind, CommandInvocation, RuleConfig};

fn bench_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("HOME must be set for omamori bench");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let parent = home.join(".cache");
    fs::create_dir_all(&parent).expect("create $HOME/.cache");
    let dir = parent.join(format!(
        "omamori-bench-audit-{}-{}",
        std::process::id(),
        nonce
    ));
    // `create_dir` (not `_all`) refuses any pre-existing path, including a
    // stale dir from a previous bench process or a symlink pre-planted in
    // `$HOME/.cache`. With the PID+nanos nonce a same-process collision is
    // extremely unlikely, so AlreadyExists here means the environment is
    // suspicious and we want to abort rather than write into it
    // (defense-in-depth alongside omamori's own protections).
    fs::create_dir(&dir).expect("create unique bench dir");
    dir
}

fn make_logger(dir: &Path) -> AuditLogger {
    let config = AuditConfig {
        enabled: true,
        path: Some(dir.join("audit.jsonl")),
        retention_days: 0,
        strict: false,
    };
    AuditLogger::from_config(&config).expect("logger constructs in writable bench dir")
}

fn make_event(logger: &AuditLogger) -> AuditEvent {
    let invocation = CommandInvocation::new(
        "rm".to_string(),
        vec!["-rf".to_string(), "/tmp/omamori-bench-target".to_string()],
    );
    let rule = RuleConfig::new(
        "rm-rf-root",
        "rm",
        ActionKind::Block,
        vec!["-rf".to_string()],
        vec![],
        Some("rm -rf safeguard".to_string()),
    );
    let outcome = ActionOutcome::Blocked {
        message: "blocked by omamori".to_string(),
    };
    let detectors = vec!["claude_code".to_string()];
    logger.create_event(&invocation, Some(&rule), &detectors, &outcome)
}

fn bench_append_single_event(c: &mut Criterion) {
    static SETUP: OnceLock<(AuditLogger, AuditEvent)> = OnceLock::new();
    let (logger, template_event) = SETUP.get_or_init(|| {
        let dir = bench_dir();
        let logger = make_logger(&dir);
        // Without an HMAC secret the `append()` path takes the
        // `NO_HMAC_SECRET` branch in `src/audit/secret.rs`. That is a
        // legitimate runtime mode but it skips the HMAC entry-hash
        // computation that the CHANGELOG advertises this bench measures.
        // Hard-fail here so a misconfigured environment cannot silently
        // produce numbers that misrepresent the audit-append cost.
        assert!(
            logger.secret_available(),
            "audit bench requires an HMAC secret; check $HOME/.cache \
             permissions or omamori install state in the bench dir"
        );
        let event = make_event(&logger);
        (logger, event)
    });

    c.bench_function("audit/append/single_event", |b| {
        b.iter_batched(
            || template_event.clone(),
            |evt| {
                logger
                    .append(black_box(evt))
                    .expect("append must succeed in bench")
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_append_single_event);
criterion_main!(benches);
