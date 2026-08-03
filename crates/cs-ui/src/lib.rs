//! config-sync user-facing surface: an interactive terminal conflict resolver.
//!
//! Kept in a separate crate so the pure-logic `cs-sync` crate stays free of
//! terminal/IO dependencies. The resolver implements `cs_sync::ConflictResolver`
//! and prompts the user with a menu for each conflict, optionally showing a
//! decrypted preview of each side.

#![forbid(unsafe_code)]

mod resolver;

pub use resolver::{ConflictPreview, FakeInteractive, InteractiveResolver, InteractiveSurface};

#[cfg(feature = "terminal")]
pub use resolver::TerminalInteractive;
