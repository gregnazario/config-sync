use crate::clock::VectorClock;
use crate::entry::{Entry, ResolutionRecord};
use crate::types::ConfigPath;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The single mutable coordination object on a store. Every mutation goes
/// through a conditional put keyed on `manifest_version` (CAS).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    /// Last writer (diagnostics only; not authoritative).
    pub device_id: String,
    /// Aggregate causal clock across all paths.
    pub clock: VectorClock,
    pub entries: BTreeMap<ConfigPath, Entry>,
    pub resolutions: BTreeMap<ConfigPath, ResolutionRecord>,
    /// Monotonic; incremented on every successful push and used for CAS.
    pub manifest_version: u64,
}

impl Manifest {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            device_id: device_id.into(),
            clock: VectorClock::new(),
            entries: BTreeMap::new(),
            resolutions: BTreeMap::new(),
            manifest_version: 0,
        }
    }

    /// Postcard encoding. Entry ordering is deterministic (BTreeMap), but
    /// `SystemTime` fields mean byte-equality is NOT guaranteed for manifests
    /// that differ only in wall-clock timestamps. Convergence relies on
    /// `manifest_version` (monotonic), not byte-equality.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::ManifestError> {
        postcard::to_allocvec(self).map_err(|e| crate::error::ManifestError::Decode(e.to_string()))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, crate::error::ManifestError> {
        let m: Manifest = postcard::from_bytes(b)
            .map_err(|e| crate::error::ManifestError::Decode(e.to_string()))?;
        if m.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(crate::error::ManifestError::SchemaVersion(m.schema_version));
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeviceId, Sha256};
    use std::time::SystemTime;

    #[test]
    fn manifest_round_trips() {
        let mut m = Manifest::new("dev-A");
        m.clock.bump(&DeviceId::new("dev-A"));
        m.entries.insert(
            ConfigPath::new("vim/.vimrc"),
            Entry {
                blob_id: Sha256::of(b"x"),
                content_hash: Sha256::of(b"x"),
                aad_version: 1,
                clock: m.clock.clone(),
                size: 1,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        let bytes = m.to_bytes().unwrap();
        let back = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn encoding_is_deterministic() {
        let m = Manifest::new("dev-A");
        assert_eq!(m.to_bytes().unwrap(), m.to_bytes().unwrap());
    }

    #[test]
    fn rejects_unknown_schema_version() {
        // Hand-craft a manifest with a wrong schema_version via raw map.
        let mut bad = Manifest::new("x");
        bad.schema_version = 99;
        let bytes = postcard::to_allocvec(&bad).unwrap();
        assert!(Manifest::from_bytes(&bytes).is_err());
    }

    #[test]
    fn entries_are_sorted_by_path() {
        let mut m = Manifest::new("a");
        m.entries.insert(
            ConfigPath::new("z"),
            Entry {
                blob_id: Sha256::of(b"z"),
                content_hash: Sha256::of(b"z"),
                aad_version: 1,
                clock: VectorClock::new(),
                size: 1,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        m.entries.insert(
            ConfigPath::new("a"),
            Entry {
                blob_id: Sha256::of(b"a"),
                content_hash: Sha256::of(b"a"),
                aad_version: 1,
                clock: VectorClock::new(),
                size: 1,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        let keys: Vec<_> = m.entries.keys().map(|p| p.as_str()).collect();
        assert_eq!(keys, vec!["a", "z"]);
    }
}
