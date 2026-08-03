//! Interactive conflict resolution.
//!
//! [`InteractiveResolver`] implements [`cs_sync::ConflictResolver`] and asks the
//! user how to handle each conflict via an [`InteractiveSurface`]. The surface
//! abstraction lets tests drive the resolver with a fake stdin/stdout, while the
//! [`TerminalInteractive`] (behind the `terminal` feature) wraps `dialoguer` for
//! real interactive use.

use cs_manifest::ConfigPath;
use cs_sync::{Conflict, ConflictChoice, ConflictResolver, SyncError};
use std::sync::Mutex;

/// A short, human-readable preview of one side of a conflict (path + a few
/// lines of decrypted content). The sync engine supplies previews via a
/// callback so this crate never has to do crypto or I/O itself.
#[derive(Clone, Debug)]
pub struct ConflictPreview {
    pub path: ConfigPath,
    /// A short label like "local" / "remote".
    pub side: &'static str,
    /// Optional first-line preview of the decrypted content (truncated).
    pub preview: Option<String>,
    pub size: u64,
}

/// Abstraction over the interactive prompt so the resolver is unit-testable.
/// `present` displays the conflict and returns the user's choice, or `None`
/// for the "abort" selection.
pub trait InteractiveSurface: Send + Sync {
    fn present(&self, previews: &[ConflictPreview]) -> Result<Option<ConflictChoice>, SyncError>;
}

/// Which side of a conflict to preview.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictSide {
    Local,
    Remote,
}

/// Preview callback: produces an optional [`ConflictPreview`] for a side. Must
/// be `Sync` so the resolver can be passed as `&dyn ConflictResolver: Send+Sync`.
pub type PreviewFn<'a> = &'a (dyn Fn(&Conflict, ConflictSide) -> Option<ConflictPreview> + Sync);

/// The interactive resolver. `preview` is invoked twice per conflict (local and
/// remote) to produce the previews shown to the user; pass `None` if previews
/// are unavailable (e.g. headless with no decrypted blobs handy).
pub struct InteractiveResolver<'a> {
    surface: &'a dyn InteractiveSurface,
    preview: Option<PreviewFn<'a>>,
}

impl<'a> InteractiveResolver<'a> {
    pub fn new(surface: &'a dyn InteractiveSurface) -> Self {
        Self {
            surface,
            preview: None,
        }
    }

    pub fn with_preview(mut self, preview: PreviewFn<'a>) -> Self {
        self.preview = Some(preview);
        self
    }
}

impl<'a> ConflictResolver for InteractiveResolver<'a> {
    fn resolve(&self, conflict: &Conflict) -> Result<ConflictChoice, SyncError> {
        let mut previews = Vec::with_capacity(2);
        if let Some(f) = self.preview {
            if let Some(p) = f(conflict, ConflictSide::Local) {
                previews.push(p);
            } else {
                previews.push(bare_preview(&conflict.path, "local", conflict.local.size));
            }
            if let Some(p) = f(conflict, ConflictSide::Remote) {
                previews.push(p);
            } else {
                previews.push(bare_preview(&conflict.path, "remote", conflict.remote.size));
            }
        } else {
            previews.push(bare_preview(&conflict.path, "local", conflict.local.size));
            previews.push(bare_preview(&conflict.path, "remote", conflict.remote.size));
        }
        match self.surface.present(&previews)? {
            Some(c) => Ok(c),
            None => Ok(ConflictChoice::Abort),
        }
    }
}

fn bare_preview(path: &ConfigPath, side: &'static str, size: u64) -> ConflictPreview {
    ConflictPreview {
        path: path.clone(),
        side,
        preview: None,
        size,
    }
}

/// A fake interactive surface for tests: returns a pre-programmed answer (or
/// `None` to simulate abort). Wrapped in a `Mutex` so it can be `&dyn` shared.
pub struct FakeInteractive {
    pub answer: Mutex<Option<Option<ConflictChoice>>>,
    pub seen: Mutex<Vec<Vec<ConflictPreview>>>,
}

impl FakeInteractive {
    pub fn returning(choice: Option<ConflictChoice>) -> Self {
        Self {
            answer: Mutex::new(Some(choice)),
            seen: Mutex::new(Vec::new()),
        }
    }

    pub fn aborting() -> Self {
        Self::returning(None)
    }
}

impl InteractiveSurface for FakeInteractive {
    fn present(&self, previews: &[ConflictPreview]) -> Result<Option<ConflictChoice>, SyncError> {
        self.seen.lock().unwrap().push(previews.to_vec());
        let mut a = self.answer.lock().unwrap();
        a.take().ok_or(SyncError::Aborted)
    }
}

/// Terminal-backed interactive surface using `dialoguer`. Behind the `terminal`
/// feature; absent it, this type does not exist and `cs-ui` has no IO deps.
#[cfg(feature = "terminal")]
pub struct TerminalInteractive;

#[cfg(feature = "terminal")]
impl TerminalInteractive {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "terminal")]
impl Default for TerminalInteractive {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "terminal")]
impl InteractiveSurface for TerminalInteractive {
    fn present(&self, previews: &[ConflictPreview]) -> Result<Option<ConflictChoice>, SyncError> {
        use console::style;
        use dialoguer::{theme::ColorfulTheme, Select};

        if previews.is_empty() {
            return Ok(Some(ConflictChoice::KeepLocal));
        }
        let path = &previews[0].path;
        eprintln!(
            "{} conflict on {}",
            style("conflict").yellow().bold(),
            style(path.as_str()).cyan()
        );
        for p in previews {
            match &p.preview {
                Some(text) => {
                    eprintln!("  {} ({} bytes): {}", style(p.side).magenta(), p.size, text)
                }
                None => eprintln!(
                    "  {} ({} bytes): <no preview>",
                    style(p.side).magenta(),
                    p.size
                ),
            }
        }

        let items = [
            "Keep local",
            "Keep remote",
            "Keep both (write remote as <path>.remote)",
            "Abort this sync",
        ];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("How should this conflict be resolved?")
            .items(&items)
            .default(0)
            .interact_opt()
            .map_err(|e| SyncError::Manifest(format!("interactive prompt failed: {e}")))?;

        Ok(match selection {
            Some(0) => Some(ConflictChoice::KeepLocal),
            Some(1) => Some(ConflictChoice::KeepRemote),
            Some(2) => Some(ConflictChoice::KeepBoth),
            Some(3) => None,
            _ => Some(ConflictChoice::KeepLocal),
        })
    }
}

#[cfg(all(test, not(feature = "terminal")))]
mod tests {
    use super::*;
    use cs_manifest::{DeviceId, Entry, Sha256, VectorClock};
    use std::time::SystemTime;

    fn entry(blob: &[u8], dev: &str) -> Entry {
        let mut c = VectorClock::new();
        c.bump(&DeviceId::new(dev));
        Entry {
            blob_id: Sha256::of(blob),
            content_hash: Sha256::of(blob),
            aad_version: 1,
            clock: c,
            size: blob.len() as u64,
            modified: SystemTime::UNIX_EPOCH,
            deleted: false,
        }
    }

    fn sample_conflict() -> Conflict {
        Conflict {
            path: ConfigPath::new("vim/.vimrc"),
            local: entry(b"set nu\n", "A"),
            remote: entry(b"set rnu\n", "B"),
        }
    }

    #[test]
    fn returns_programmed_choice() {
        let surf = FakeInteractive::returning(Some(ConflictChoice::KeepRemote));
        let r = InteractiveResolver::new(&surf);
        assert_eq!(
            r.resolve(&sample_conflict()).unwrap(),
            ConflictChoice::KeepRemote
        );
        // The surface saw exactly one prompt with two previews.
        let seen = surf.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].len(), 2);
        assert_eq!(seen[0][0].side, "local");
        assert_eq!(seen[0][1].side, "remote");
    }

    #[test]
    fn abort_surfaces_as_abort_choice() {
        let surf = FakeInteractive::aborting();
        let r = InteractiveResolver::new(&surf);
        assert_eq!(
            r.resolve(&sample_conflict()).unwrap(),
            ConflictChoice::Abort
        );
    }

    #[test]
    fn preview_callback_is_used_when_provided() {
        let surf = FakeInteractive::returning(Some(ConflictChoice::KeepLocal));
        let preview = |c: &Conflict, side: ConflictSide| {
            let (label, e) = match side {
                ConflictSide::Local => ("local", &c.local),
                ConflictSide::Remote => ("remote", &c.remote),
            };
            Some(ConflictPreview {
                path: c.path.clone(),
                side: label,
                preview: Some(format!("{} bytes", e.size)),
                size: e.size,
            })
        };
        let r = InteractiveResolver::new(&surf).with_preview(&preview);
        r.resolve(&sample_conflict()).unwrap();
        let seen = surf.seen.lock().unwrap();
        assert_eq!(seen[0][0].preview.as_deref(), Some("7 bytes")); // "set nu\n"
    }

    #[test]
    fn second_call_without_rearming_aborts() {
        // FakeInteractive only holds one answer; a second resolve surfaces an
        // error that the engine treats as abort.
        let surf = FakeInteractive::returning(Some(ConflictChoice::KeepLocal));
        let r = InteractiveResolver::new(&surf);
        let _ = r.resolve(&sample_conflict()).unwrap();
        let second = r.resolve(&sample_conflict());
        assert!(second.is_err(), "an unarmed fake surface should error");
    }
}

#[cfg(all(test, feature = "terminal"))]
mod terminal_tests {
    use super::*;
    use cs_manifest::{ConfigPath, DeviceId, Entry, Sha256, VectorClock};
    use std::time::SystemTime;

    fn entry(blob: &[u8], dev: &str) -> Entry {
        let mut c = VectorClock::new();
        c.bump(&DeviceId::new(dev));
        Entry {
            blob_id: Sha256::of(blob),
            content_hash: Sha256::of(blob),
            aad_version: 1,
            clock: c,
            size: blob.len() as u64,
            modified: SystemTime::UNIX_EPOCH,
            deleted: false,
        }
    }

    #[test]
    fn terminal_compiles_and_constructs() {
        // The terminal surface reads real stdin; we only assert it builds and
        // the resolver wires up. Interactive behavior is verified manually.
        let _t = TerminalInteractive::new();
        let c = Conflict {
            path: ConfigPath::new("vim/.vimrc"),
            local: entry(b"a", "A"),
            remote: entry(b"b", "B"),
        };
        let _r = InteractiveResolver::new(&TerminalInteractive::new());
        let _ = &c;
    }
}
