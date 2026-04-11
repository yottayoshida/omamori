#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the PreToolUse hook input parser (JSON → HookInput classification).
// Goal: no panics on arbitrary input, including malformed JSON and edge cases.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        omamori::fuzz_extract_hook_input(s);
    }
});
