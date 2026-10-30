#![forbid(unsafe_code)]
use std::path::PathBuf;
use std::process::ExitCode;

use pqvpnd::connect::ConnectError;

fn main() -> ExitCode {
    // First, before any thread exists: stop signals are only ever taken synchronously (signalfd), so a
    // SIGTERM during setup waits and cleanup always runs through drop.
    let signals = match pqvpnd::block_stop_signals() {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("pqvpnd: cannot block signals: {error}");
            return ExitCode::FAILURE;
        }
    };
    let args: Vec<String> = std::env::args().collect();
    let config = match args.as_slice() {
        [_, command, flag, path] if command == "connect" && flag == "--config" => PathBuf::from(path),
        _ => {
            eprintln!("usage: pqvpnd connect --config CLIENT_TOML");
            return ExitCode::from(2);
        }
    };
    match pqvpnd::connect::connect(&config, &signals) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pqvpnd: {error}");
            ExitCode::from(if matches!(error, ConnectError::Config(_)) { 2 } else { 1 })
        }
    }
}
