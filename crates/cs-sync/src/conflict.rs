use cs_config::ConflictPolicy;
use cs_manifest::{ConfigPath, Entry, ResolutionRecord, Sha256, VectorClock};
use std::time::SystemTime;

/// User-facing choice when prompted about a conflict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictChoice {
    KeepLocal,
    KeepRemote,
    KeepBoth,
    Abort,
}

/// A single path that diverged concurrently on two devices.
#[derive(Clone, Debug)]
pub struct Conflict {
    pub path: ConfigPath,
    pub local: Entry,
    pub remote: Entry,
}

/// Interactive conflict resolution hook. The engine calls `resolve` for each
/// `ConflictPolicy::Prompt` conflict; a default terminal implementation lives
/// at a higher layer, and tests inject a [`FixedResolver`].
pub trait ConflictResolver: Send + Sync {
    fn resolve(&self, conflict: &Conflict) -> Result<ConflictChoice, crate::SyncError>;
}

/// A resolver that always returns a fixed choice — for tests and headless runs.
pub struct FixedResolver(pub ConflictChoice);

impl ConflictResolver for FixedResolver {
    fn resolve(&self, _c: &Conflict) -> Result<ConflictChoice, crate::SyncError> {
        Ok(self.0.clone())
    }
}

/// Outcome of resolving a conflict: which entry wins and which blobs it
/// supersedes, or an abort that stops the sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Resolved {
        chosen: Entry,
        superseded: Vec<Sha256>,
        record_clock: VectorClock,
    },
    Aborted,
}

/// Apply a policy (and optional interactive choice) to a conflict. `now` is
/// passed in so tests can be deterministic.
pub fn resolve_conflict(
    conflict: &Conflict,
    policy: ConflictPolicy,
    resolver: Option<&dyn ConflictResolver>,
    _manifest_version: u64,
    _now: SystemTime,
) -> Result<Resolution, crate::SyncError> {
    let choice = match policy {
        ConflictPolicy::LatestWins => {
            // Tie-break deterministically by lexicographic blob id so both
            // devices converge to the same choice with no communication.
            if conflict.local.modified > conflict.remote.modified {
                ConflictChoice::KeepLocal
            } else if conflict.local.modified < conflict.remote.modified {
                ConflictChoice::KeepRemote
            } else if conflict.local.blob_id >= conflict.remote.blob_id {
                ConflictChoice::KeepLocal
            } else {
                ConflictChoice::KeepRemote
            }
        }
        ConflictPolicy::Prompt => {
            let r = resolver.ok_or(crate::SyncError::UnresolvedConflict)?;
            r.resolve(conflict)?
        }
        // Manual surfaces both versions; the engine writes the remote side
        // alongside as <path>.remote and keeps local as the manifest entry.
        ConflictPolicy::Manual => ConflictChoice::KeepBoth,
    };

    Ok(match choice {
        ConflictChoice::Abort => Resolution::Aborted,
        ConflictChoice::KeepLocal => Resolution::Resolved {
            chosen: conflict.local.clone(),
            superseded: vec![conflict.remote.blob_id.clone()],
            record_clock: conflict.local.clock.clone(),
        },
        ConflictChoice::KeepRemote => Resolution::Resolved {
            chosen: conflict.remote.clone(),
            superseded: vec![conflict.local.blob_id.clone()],
            record_clock: conflict.remote.clock.clone(),
        },
        ConflictChoice::KeepBoth => Resolution::Resolved {
            chosen: conflict.local.clone(),
            superseded: vec![conflict.remote.blob_id.clone()],
            record_clock: {
                let mut c = conflict.local.clock.clone();
                c.merge(&conflict.remote.clock);
                c
            },
        },
    })
}

/// Build a `ResolutionRecord` from a `Resolution`, if it was not aborted.
pub fn make_record(resolution: &Resolution, manifest_version: u64) -> Option<ResolutionRecord> {
    match resolution {
        Resolution::Resolved {
            chosen,
            superseded,
            record_clock,
        } => Some(ResolutionRecord {
            at_version: manifest_version,
            chosen_blob: chosen.blob_id.clone(),
            superseded: superseded.clone(),
            clock: record_clock.clone(),
        }),
        Resolution::Aborted => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cs_manifest::DeviceId;
    use std::time::Duration;

    fn entry(blob: &[u8], dev: &str, t: SystemTime) -> Entry {
        let mut c = VectorClock::new();
        c.bump(&DeviceId::new(dev));
        Entry {
            blob_id: Sha256::of(blob),
            content_hash: Sha256::of(blob),
            aad_version: 1,
            clock: c,
            size: blob.len() as u64,
            modified: t,
            deleted: false,
        }
    }

    fn conflict(local_time: SystemTime, remote_time: SystemTime) -> Conflict {
        Conflict {
            path: ConfigPath::new("p"),
            local: entry(b"local", "A", local_time),
            remote: entry(b"remote", "B", remote_time),
        }
    }

    #[test]
    fn latest_wins_picks_newer() {
        let c = conflict(
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        );
        let r = resolve_conflict(
            &c,
            ConflictPolicy::LatestWins,
            None,
            1,
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        match r {
            Resolution::Resolved { chosen, .. } => {
                assert_eq!(chosen.blob_id, Sha256::of(b"remote"))
            }
            _ => panic!("expected resolved"),
        }
    }

    #[test]
    fn latest_wins_tiebreak_is_deterministic() {
        // Same mtime → tie-break by blob id. "remote" > "local" lexicographically,
        // so the remote blob (Sha256(b"remote")) wins.
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
        let r = resolve_conflict(
            &c,
            ConflictPolicy::LatestWins,
            None,
            1,
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        match r {
            Resolution::Resolved { chosen, .. } => {
                assert_eq!(chosen.blob_id, Sha256::of(b"remote"))
            }
            _ => panic!("expected resolved"),
        }
    }

    #[test]
    fn prompt_uses_resolver() {
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
        let res = FixedResolver(ConflictChoice::KeepLocal);
        let r = resolve_conflict(
            &c,
            ConflictPolicy::Prompt,
            Some(&res),
            1,
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        match r {
            Resolution::Resolved { chosen, .. } => assert_eq!(chosen.blob_id, Sha256::of(b"local")),
            _ => panic!("expected resolved"),
        }
    }

    #[test]
    fn prompt_without_resolver_errors() {
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
        assert!(matches!(
            resolve_conflict(&c, ConflictPolicy::Prompt, None, 1, SystemTime::UNIX_EPOCH),
            Err(crate::SyncError::UnresolvedConflict)
        ));
    }

    #[test]
    fn abort_propagates() {
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
        let res = FixedResolver(ConflictChoice::Abort);
        let r = resolve_conflict(
            &c,
            ConflictPolicy::Prompt,
            Some(&res),
            1,
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(r, Resolution::Aborted);
    }

    #[test]
    fn manual_merges_clocks() {
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
        let r =
            resolve_conflict(&c, ConflictPolicy::Manual, None, 1, SystemTime::UNIX_EPOCH).unwrap();
        match r {
            Resolution::Resolved { record_clock, .. } => {
                assert_eq!(record_clock.get(&DeviceId::new("A")), 1);
                assert_eq!(record_clock.get(&DeviceId::new("B")), 1);
            }
            _ => panic!("expected resolved"),
        }
    }

    #[test]
    fn make_record_round_trips_resolved() {
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
        let r = resolve_conflict(
            &c,
            ConflictPolicy::LatestWins,
            None,
            1,
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert!(make_record(&r, 5).is_some());
        assert!(make_record(&Resolution::Aborted, 5).is_none());
    }
}
