use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(pub String);

impl DeviceId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigPath(pub String);

impl ConfigPath {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A 32-byte content hash; hex-encoded for blob ids.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn of(data: &[u8]) -> Self {
        use sha2::{Digest, Sha256 as S};
        let mut h = S::new();
        h.update(data);
        let out = h.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(&out);
        Self(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_is_known_constant() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = Sha256::of(b"");
        assert_eq!(
            h.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_data_is_deterministic() {
        assert_eq!(Sha256::of(b"hello"), Sha256::of(b"hello"));
        assert_ne!(Sha256::of(b"hello"), Sha256::of(b"world"));
    }

    #[test]
    fn config_path_orders_lexicographically() {
        let a = ConfigPath::new("a/b");
        let b = ConfigPath::new("a/c");
        assert!(a < b);
    }

    #[test]
    fn device_id_round_trips_through_serde() {
        let d = DeviceId::new("device-7");
        let s = postcard::to_allocvec(&d).unwrap();
        let back: DeviceId = postcard::from_bytes(&s).unwrap();
        assert_eq!(d, back);
    }
}
