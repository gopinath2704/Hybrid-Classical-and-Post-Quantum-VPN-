#![forbid(unsafe_code)]
//! `pqvpnd connect`: the native one-shot client (phase 4 slice d).
pub mod config;
pub mod connect;
pub mod identity;
pub mod net;

use nix::sys::signal::{SigSet, Signal};

/// Blocks SIGTERM, SIGINT and SIGHUP in the calling thread (call it first, before any thread starts, so every
/// thread inherits the mask). A stop request that arrives mid-setup then waits until `wait_for_stop`, and
/// cleanup always runs through the normal drop path instead of an async signal handler.
pub fn block_stop_signals() -> nix::Result<SigSet> {
    let mut set = SigSet::empty();
    for signal in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP] {
        set.add(signal);
    }
    set.thread_block()?;
    Ok(set)
}

/// Waits for one of the blocked stop signals and returns it.
pub fn wait_for_stop(set: &SigSet) -> nix::Result<Signal> {
    set.wait()
}
