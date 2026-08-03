//! `config-sync` — the user-facing CLI binary.
//!
//! Thin entry point: parse args and hand off to [`cs_cli::run`]. All real
//! logic lives in the library so it is unit-testable.

#![forbid(unsafe_code)]

use clap::Parser;
use cs_cli::{Cli, CliError};

fn main() {
    let cli = Cli::parse();
    match cs_cli::run(&cli) {
        Ok(()) => {}
        Err(CliError::Plain(msg)) => {
            eprintln!("error: {msg}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
