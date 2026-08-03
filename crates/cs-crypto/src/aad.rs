use serde::{Deserialize, Serialize};

/// Authenticated additional data bound into every AEAD call: path + version.
/// Prevents relocation/replay of a ciphertext against a different file/version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aad {
    pub path: String,
    pub version: u64,
}

impl Aad {
    /// Canonical, deterministic encoding used as AEAD AAD bytes.
    /// Layout: 8-byte LE version + 8-byte LE path length + path bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.path.len());
        out.extend_from_slice(&self.version.to_le_bytes());
        let plen = self.path.len() as u64;
        out.extend_from_slice(&plen.to_le_bytes());
        out.extend_from_slice(self.path.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_is_deterministic() {
        let a = Aad {
            path: "~/.vimrc".into(),
            version: 7,
        };
        let b = Aad {
            path: "~/.vimrc".into(),
            version: 7,
        };
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn different_versions_encode_differently() {
        let a = Aad {
            path: "p".into(),
            version: 1,
        };
        let b = Aad {
            path: "p".into(),
            version: 2,
        };
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn different_paths_encode_differently() {
        let a = Aad {
            path: "p1".into(),
            version: 1,
        };
        let b = Aad {
            path: "p2".into(),
            version: 1,
        };
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn empty_path_is_supported() {
        let a = Aad {
            path: String::new(),
            version: 0,
        };
        let enc = a.encode();
        assert_eq!(enc.len(), 16); // 8 version + 8 len(0) + 0 path
    }
}
