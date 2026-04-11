#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the full hook check pipeline: meta-patterns + unwrap stack + rule matching.
// Goal: no panics on arbitrary command strings.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        omamori::fuzz_check_command_for_hook(s);
    }
});
