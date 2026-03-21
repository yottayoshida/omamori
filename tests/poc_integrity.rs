//! PoC tests for v0.5.0 integrity monitoring.
//!
//! These tests verify three critical assumptions before implementation:
//! - PoC-1: render_hook_script() produces deterministic output
//! - PoC-2: stat + readlink syscalls are < 0.1ms
//! - PoC-3: hook regeneration + hash comparison work in correct order

use sha2::{Digest, Sha256};
use std::os::unix::fs::symlink;
use std::time::Instant;

/// PoC-1: render_hook_script() determinism
///
/// If the output changes between calls, content hash comparison will
/// always show "mismatch" and trigger unnecessary regeneration.
#[test]
fn poc1_render_hook_script_is_deterministic() {
    let output1 = omamori::installer::render_hook_script();
    let output2 = omamori::installer::render_hook_script();

    // Same content
    assert_eq!(
        output1, output2,
        "render_hook_script() is not deterministic"
    );

    // Same hash
    let hash1 = sha256_hex(&output1);
    let hash2 = sha256_hex(&output2);
    assert_eq!(hash1, hash2, "SHA-256 hashes differ between calls");

    // Verify no obvious dynamic content (timestamps, PIDs, etc.)
    assert!(
        !output1.contains(&std::process::id().to_string()),
        "Hook script contains PID — not deterministic across processes"
    );

    println!("PoC-1 PASS: render_hook_script() SHA-256 = {}", hash1);
}

/// PoC-1b: render_hook_script() contains version but nothing else dynamic
#[test]
fn poc1b_render_hook_script_only_dynamic_is_version() {
    let output = omamori::installer::render_hook_script();

    // Should contain version
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        output.contains(version),
        "Hook script does not contain CARGO_PKG_VERSION"
    );

    // Replace version with placeholder and check it's still deterministic
    let normalized1 = output.replace(version, "VERSION");
    let normalized2 = omamori::installer::render_hook_script().replace(version, "VERSION");
    assert_eq!(normalized1, normalized2);

    println!("PoC-1b PASS: only dynamic content is version ({})", version);
}

/// PoC-2: stat + readlink latency benchmark
///
/// Budget: < 0.1ms per invocation (canary check on every shim call).
/// Measures 100 iterations and reports median.
#[test]
fn poc2_stat_readlink_latency() {
    let dir = std::env::temp_dir().join(format!("omamori-poc2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Create a symlink (simulating ~/.omamori/shim/rm -> omamori binary)
    let link_path = dir.join("test-link");
    let target = std::env::current_exe().unwrap();
    let _ = std::fs::remove_file(&link_path);
    symlink(&target, &link_path).unwrap();

    // Create a file (simulating .integrity.json)
    let json_path = dir.join(".integrity.json");
    std::fs::write(&json_path, r#"{"version":"0.5.0"}"#).unwrap();

    // Warm up
    for _ in 0..10 {
        let _ = std::fs::symlink_metadata(&json_path);
        let _ = std::fs::read_link(&link_path);
    }

    // Benchmark: stat + readlink (the canary check)
    let mut durations = Vec::with_capacity(100);
    for _ in 0..100 {
        let start = Instant::now();

        // This is what integrity_canary() would do:
        let _meta = std::fs::symlink_metadata(&json_path); // stat
        let _target = std::fs::read_link(&link_path); // readlink

        durations.push(start.elapsed());
    }

    durations.sort();
    let median = durations[50];
    let p99 = durations[99];

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);

    println!("PoC-2 results (N=100):");
    println!("  Median: {:?}", median);
    println!("  P99:    {:?}", p99);
    println!("  Budget: 0.1ms = 100µs = 100,000ns");

    // Assert median < 0.1ms (100µs)
    assert!(
        median.as_micros() < 100,
        "Median latency {:?} exceeds 0.1ms budget",
        median
    );

    println!("PoC-2 PASS: median {:?} < 0.1ms", median);
}

/// PoC-3: hook regeneration + hash comparison ordering
///
/// Simulates the flow:
/// 1. Write a hook file with "old" content
/// 2. Regenerate (overwrite with render_hook_script())
/// 3. Immediately compare hash of file vs render_hook_script()
/// 4. They should match (no false positive)
#[test]
fn poc3_hook_regen_then_hash_check_no_false_positive() {
    let dir = std::env::temp_dir().join(format!("omamori-poc3-{}", std::process::id()));
    let hooks_dir = dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();

    let hook_path = hooks_dir.join("claude-pretooluse.sh");

    // Step 1: Write "old" hook content (simulating v0.4 hook)
    std::fs::write(
        &hook_path,
        "#!/bin/sh\n# omamori hook v0.4.0\nold content\n",
    )
    .unwrap();

    // Verify they DON'T match before regen
    let expected = omamori::installer::render_hook_script();
    let expected_hash = sha256_hex(&expected);
    let actual_before = std::fs::read_to_string(&hook_path).unwrap();
    let actual_hash_before = sha256_hex(&actual_before);
    assert_ne!(
        expected_hash, actual_hash_before,
        "Pre-regen: hashes should differ"
    );

    // Step 2: Regenerate (simulating ensure_hooks_current -> regenerate_hooks)
    std::fs::write(&hook_path, &expected).unwrap();

    // Step 3: Immediately compare hash
    let actual_after = std::fs::read_to_string(&hook_path).unwrap();
    let actual_hash_after = sha256_hex(&actual_after);

    // Step 4: Should match (no false positive)
    assert_eq!(
        expected_hash, actual_hash_after,
        "Post-regen: hash mismatch! False positive would occur.\nExpected: {}\nActual:   {}",
        expected_hash, actual_hash_after
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);

    println!("PoC-3 PASS: post-regen hash matches render_hook_script()");
}

/// PoC-3b: Tampered hook (version preserved, content changed) is detected
#[test]
fn poc3b_tampered_hook_detected_by_hash() {
    let expected = omamori::installer::render_hook_script();
    let expected_hash = sha256_hex(&expected);

    // Simulate T2 attack: keep version comment, change exit codes
    let tampered = expected.replace("exit 2", "exit 0");
    let tampered_hash = sha256_hex(&tampered);

    // Version comment is preserved
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        tampered.contains(&format!("# omamori hook v{}", version)),
        "Tampered script should still have version comment"
    );

    // But hash is different
    assert_ne!(
        expected_hash, tampered_hash,
        "Tampered hook should have different hash"
    );

    println!("PoC-3b PASS: T2 attack (version-preserved tampering) detected by hash");
    println!("  Original: {}", expected_hash);
    println!("  Tampered: {}", tampered_hash);
}

fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}
