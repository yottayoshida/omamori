use std::ffi::OsString;
use std::process;

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    match omamori::run(&args) {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}
