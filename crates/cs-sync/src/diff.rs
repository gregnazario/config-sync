use cs_manifest::{ConfigPath, Entry, Manifest};
use std::collections::BTreeSet;

/// What the engine should do for one path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffOp {
    /// Remote has it, local doesn't (or remote is strictly newer) → pull.
    PullLocal { path: ConfigPath, remote: Entry },
    /// Local has it and is strictly newer → push.
    PushRemote { path: ConfigPath, local: Entry },
    /// Both have it, identical → no-op.
    InSync { path: ConfigPath },
    /// Concurrent edits → conflict.
    Conflict {
        path: ConfigPath,
        local: Entry,
        remote: Entry,
    },
    /// Remote tombstoned past local → propagate deletion locally.
    PullDeletion { path: ConfigPath, remote: Entry },
    /// Local tombstoned past remote → push deletion.
    PushDeletion { path: ConfigPath, local: Entry },
}

/// Compute the diff between local and remote manifests. The result drives the
/// sync engine: pulls, pushes, no-ops, and conflicts.
pub fn diff(local: &Manifest, remote: &Manifest) -> Vec<DiffOp> {
    let paths: BTreeSet<&ConfigPath> = local.entries.keys().chain(remote.entries.keys()).collect();
    let mut out = Vec::new();
    for p in paths {
        match (
            local.entries.get(p).cloned(),
            remote.entries.get(p).cloned(),
        ) {
            (None, Some(r)) => {
                if r.deleted {
                    out.push(DiffOp::PullDeletion {
                        path: p.clone(),
                        remote: r,
                    });
                } else {
                    out.push(DiffOp::PullLocal {
                        path: p.clone(),
                        remote: r,
                    });
                }
            }
            (Some(l), None) => {
                out.push(DiffOp::PushRemote {
                    path: p.clone(),
                    local: l,
                });
            }
            (Some(l), Some(r)) => {
                if l == r {
                    out.push(DiffOp::InSync { path: p.clone() });
                } else if l.clock.happens_before(&r.clock) {
                    if r.deleted {
                        out.push(DiffOp::PullDeletion {
                            path: p.clone(),
                            remote: r,
                        });
                    } else {
                        out.push(DiffOp::PullLocal {
                            path: p.clone(),
                            remote: r,
                        });
                    }
                } else if r.clock.happens_before(&l.clock) {
                    if l.deleted {
                        out.push(DiffOp::PushDeletion {
                            path: p.clone(),
                            local: l,
                        });
                    } else {
                        out.push(DiffOp::PushRemote {
                            path: p.clone(),
                            local: l,
                        });
                    }
                } else {
                    out.push(DiffOp::Conflict {
                        path: p.clone(),
                        local: l,
                        remote: r,
                    });
                }
            }
            (None, None) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cs_manifest::{DeviceId, Manifest, Sha256, VectorClock};
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

    fn tombstone(blob: &[u8], dev: &str) -> Entry {
        let mut e = entry(blob, dev);
        e.deleted = true;
        e
    }

    #[test]
    fn remote_only_is_pull() {
        let l = Manifest::new("A");
        let mut r = Manifest::new("B");
        r.entries.insert(ConfigPath::new("p"), entry(b"r", "B"));
        let d = diff(&l, &r);
        assert!(matches!(d.as_slice(), [DiffOp::PullLocal { .. }]));
    }

    #[test]
    fn local_only_is_push() {
        let mut l = Manifest::new("A");
        let r = Manifest::new("B");
        l.entries.insert(ConfigPath::new("p"), entry(b"l", "A"));
        let d = diff(&l, &r);
        assert!(matches!(d.as_slice(), [DiffOp::PushRemote { .. }]));
    }

    #[test]
    fn identical_is_in_sync() {
        let mut l = Manifest::new("A");
        let mut r = Manifest::new("A");
        let e = entry(b"x", "A");
        l.entries.insert(ConfigPath::new("p"), e.clone());
        r.entries.insert(ConfigPath::new("p"), e);
        assert!(matches!(diff(&l, &r).as_slice(), [DiffOp::InSync { .. }]));
    }

    #[test]
    fn fast_forward_pull_when_local_older() {
        let mut l = Manifest::new("A");
        let mut r = Manifest::new("A");
        let mut c1 = VectorClock::new();
        c1.bump(&DeviceId::new("A"));
        let mut c2 = c1.clone();
        c2.bump(&DeviceId::new("A"));
        l.entries.insert(
            ConfigPath::new("p"),
            Entry {
                blob_id: Sha256::of(b"v1"),
                content_hash: Sha256::of(b"v1"),
                aad_version: 1,
                clock: c1,
                size: 2,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        r.entries.insert(
            ConfigPath::new("p"),
            Entry {
                blob_id: Sha256::of(b"v2"),
                content_hash: Sha256::of(b"v2"),
                aad_version: 1,
                clock: c2,
                size: 2,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        assert!(matches!(
            diff(&l, &r).as_slice(),
            [DiffOp::PullLocal { .. }]
        ));
    }

    #[test]
    fn fast_forward_push_when_remote_older() {
        let mut l = Manifest::new("A");
        let mut r = Manifest::new("A");
        let mut c1 = VectorClock::new();
        c1.bump(&DeviceId::new("A"));
        let mut c2 = c1.clone();
        c2.bump(&DeviceId::new("A"));
        l.entries.insert(
            ConfigPath::new("p"),
            Entry {
                blob_id: Sha256::of(b"v2"),
                content_hash: Sha256::of(b"v2"),
                aad_version: 1,
                clock: c2,
                size: 2,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        r.entries.insert(
            ConfigPath::new("p"),
            Entry {
                blob_id: Sha256::of(b"v1"),
                content_hash: Sha256::of(b"v1"),
                aad_version: 1,
                clock: c1,
                size: 2,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        assert!(matches!(
            diff(&l, &r).as_slice(),
            [DiffOp::PushRemote { .. }]
        ));
    }

    #[test]
    fn concurrent_clocks_are_conflict() {
        let mut l = Manifest::new("A");
        let mut r = Manifest::new("B");
        let mut cl = VectorClock::new();
        cl.bump(&DeviceId::new("A"));
        let mut cr = VectorClock::new();
        cr.bump(&DeviceId::new("B"));
        l.entries.insert(
            ConfigPath::new("p"),
            Entry {
                blob_id: Sha256::of(b"l"),
                content_hash: Sha256::of(b"l"),
                aad_version: 1,
                clock: cl,
                size: 1,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        r.entries.insert(
            ConfigPath::new("p"),
            Entry {
                blob_id: Sha256::of(b"r"),
                content_hash: Sha256::of(b"r"),
                aad_version: 1,
                clock: cr,
                size: 1,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        assert!(matches!(diff(&l, &r).as_slice(), [DiffOp::Conflict { .. }]));
    }

    #[test]
    fn remote_tombstone_propagates_as_pull_deletion() {
        let mut l = Manifest::new("A");
        let mut r = Manifest::new("A");
        let mut c1 = VectorClock::new();
        c1.bump(&DeviceId::new("A"));
        let mut c2 = c1.clone();
        c2.bump(&DeviceId::new("A"));
        l.entries.insert(
            ConfigPath::new("p"),
            Entry {
                blob_id: Sha256::of(b"v1"),
                content_hash: Sha256::of(b"v1"),
                aad_version: 1,
                clock: c1,
                size: 2,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        r.entries
            .insert(ConfigPath::new("p"), tombstone(b"v1", "A"));
        // Override the tombstone clock so it strictly post-dates local.
        r.entries.get_mut(&ConfigPath::new("p")).unwrap().clock = c2;
        assert!(matches!(
            diff(&l, &r).as_slice(),
            [DiffOp::PullDeletion { .. }]
        ));
    }

    #[test]
    fn multiple_paths_each_get_their_op() {
        let mut l = Manifest::new("A");
        let mut r = Manifest::new("B");
        // p1: in sync; p2: pull; p3: push
        let p1 = ConfigPath::new("p1");
        let p2 = ConfigPath::new("p2");
        let p3 = ConfigPath::new("p3");
        let e1 = entry(b"s", "A");
        l.entries.insert(p1.clone(), e1.clone());
        r.entries.insert(p1, e1);
        r.entries.insert(p2, entry(b"r", "B"));
        l.entries.insert(p3, entry(b"l", "A"));
        let ops = diff(&l, &r);
        assert_eq!(ops.len(), 3);
        assert!(ops.iter().any(|o| matches!(o, DiffOp::InSync { .. })));
        assert!(ops.iter().any(|o| matches!(o, DiffOp::PullLocal { .. })));
        assert!(ops.iter().any(|o| matches!(o, DiffOp::PushRemote { .. })));
    }
}
