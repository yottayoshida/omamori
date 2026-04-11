#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the shell command parser — omamori's largest attack surface.
// Goal: no panics on arbitrary input. Hangs are caught by libFuzzer's timeout.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = omamori::unwrap::parse_command_string(s);
    }
});
