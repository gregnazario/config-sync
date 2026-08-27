//! Device identity: the long-term RIK plus the recipient keys (public + secret)
//! used to decrypt synced files on this device. The whole bundle is serialized
//! to a single blob under the `"device-identity"` account in a [`SecretStore`].

use crate::error::KeysError;
use crate::SecretStore;
use cs_crypto::{generate_rik, RecipientKeys, RecipientSecrets, Rik};
use serde::{Deserialize, Serialize};

pub struct DeviceIdentity {
    pub rik: Rik,
    pub recipient_keys: RecipientKeys,
    pub recipient_secrets: RecipientSecrets,
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct StoredIdentity {
    rik: [u8; 32],
    kem_pq_pk: Vec<u8>,
    kem_pq_sk: Vec<u8>,
    kem_classic_pk: [u8; 32],
    kem_classic_sk: [u8; 32],
}

const ACCOUNT: &str = "device-identity";

impl DeviceIdentity {
    /// Generate a fresh vault identity: a new random RIK with the recipient
    /// keys deterministically derived from it (see [`DeviceIdentity::from_rik`]).
    pub fn new() -> Result<Self, KeysError> {
        let rik = generate_rik().map_err(|e| KeysError::Recovery(e.to_string()))?;
        Ok(Self::from_rik(rik))
    }

    /// Build an identity from a RIK, deriving the recipient keys
    /// deterministically from it. Every device holding the same RIK derives
    /// byte-identical recipient keys — this is what makes recovery *work*: a
    /// recovered device can immediately decrypt every blob the vault has ever
    /// sealed, and manifests signed with the RIK-derived key verify.
    pub fn from_rik(rik: Rik) -> Self {
        let (recipient_keys, recipient_secrets) = cs_crypto::derive_recipient_keypair(&rik);
        Self {
            rik,
            recipient_keys,
            recipient_secrets,
        }
    }
}

pub fn store_identity(store: &dyn SecretStore, id: &DeviceIdentity) -> Result<(), KeysError> {
    let s = StoredIdentity {
        rik: *id.rik.as_bytes(),
        kem_pq_pk: id.recipient_keys.kem_pq.clone(),
        kem_pq_sk: id.recipient_secrets.kem_pq.clone(),
        kem_classic_pk: id.recipient_keys.kem_classic,
        kem_classic_sk: id.recipient_secrets.kem_classic,
    };
    let bytes = postcard::to_allocvec(&s).map_err(|e| KeysError::Recovery(e.to_string()))?;
    store.put(ACCOUNT, &bytes)
}

/// Validate the decoded identity payload's key lengths. A legacy identity
/// (pre ml-kem seed format: 2400-byte pqcrypto decapsulation key) or a
/// corrupt one must fail HERE with a clear message, not later inside every
/// decryption with an opaque `Kem` error.
fn validate_stored(s: &StoredIdentity) -> Result<(), KeysError> {
    if s.kem_pq_sk.len() != 64 || s.kem_pq_pk.len() != 1184 || s.kem_classic_sk.len() != 32 {
        return Err(KeysError::Recovery(
            "identity has an unsupported format: it predates the current key \
             derivation scheme (or is corrupt). Restore it with recovery material, or \
             re-initialize the vault; blobs sealed under the old scheme are unreadable \
             without the original identity"
                .into(),
        ));
    }
    Ok(())
}

pub fn load_identity(store: &dyn SecretStore) -> Result<DeviceIdentity, KeysError> {
    let bytes = store.get(ACCOUNT)?;
    load_identity_from_bytes_impl(&bytes)
}

fn load_identity_from_bytes_impl(bytes: &[u8]) -> Result<DeviceIdentity, KeysError> {
    let s: StoredIdentity =
        postcard::from_bytes(bytes).map_err(|e| KeysError::Recovery(e.to_string()))?;
    validate_stored(&s)?;
    Ok(DeviceIdentity {
        rik: Rik::from_bytes(s.rik),
        recipient_keys: RecipientKeys {
            kem_pq: s.kem_pq_pk.clone(),
            kem_classic: s.kem_classic_pk,
        },
        recipient_secrets: RecipientSecrets {
            kem_pq: s.kem_pq_sk.clone(),
            kem_classic: s.kem_classic_sk,
        },
    })
}

/// Serialize a device identity to portable postcard bytes (the same format
/// [`store_identity`] uses internally). Lets callers (e.g. the CLI) move an
/// identity between stores or files without going through `SecretStore`.
pub fn identity_to_bytes(id: &DeviceIdentity) -> Result<Vec<u8>, KeysError> {
    let s = StoredIdentity {
        rik: *id.rik.as_bytes(),
        kem_pq_pk: id.recipient_keys.kem_pq.clone(),
        kem_pq_sk: id.recipient_secrets.kem_pq.clone(),
        kem_classic_pk: id.recipient_keys.kem_classic,
        kem_classic_sk: id.recipient_secrets.kem_classic,
    };
    postcard::to_allocvec(&s).map_err(|e| KeysError::Recovery(e.to_string()))
}

/// Inverse of [`identity_to_bytes`].
pub fn load_identity_from_bytes(bytes: &[u8]) -> Result<DeviceIdentity, KeysError> {
    load_identity_from_bytes_impl(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryStore;

    #[test]
    fn store_then_load_round_trips() {
        let store = InMemoryStore::new();
        let id = DeviceIdentity::new().unwrap();
        store_identity(&store, &id).unwrap();
        let loaded = load_identity(&store).unwrap();
        assert_eq!(loaded.rik.as_bytes(), id.rik.as_bytes());
        assert_eq!(loaded.recipient_keys.kem_pq, id.recipient_keys.kem_pq);
        assert_eq!(loaded.recipient_secrets.kem_pq, id.recipient_secrets.kem_pq);
    }

    #[test]
    fn load_missing_is_not_found() {
        let store = InMemoryStore::new();
        assert!(matches!(
            load_identity(&store).err().unwrap(),
            KeysError::NotFound
        ));
    }

    #[test]
    fn stored_identity_is_encryptable_by_its_own_recipient() {
        let id = DeviceIdentity::new().unwrap();
        let aad = cs_crypto::Aad {
            path: "self".into(),
            version: 1,
        };
        let out = cs_crypto::seal(b"device-local secret", &aad, &id.recipient_keys).unwrap();
        let pt = cs_crypto::open(
            cs_crypto::OpenInput {
                header: &out.header,
                body: &out.body,
            },
            &aad,
            &id.recipient_secrets,
        )
        .unwrap();
        assert_eq!(pt, b"device-local secret");
    }

    #[test]
    fn from_rik_restores_decryption_of_existing_blobs() {
        // The core recovery property: a blob sealed by a device that derived
        // its keys from RIK X can be opened by a *different* device that only
        // ever recovered RIK X and re-derived the same keys.
        let rik = generate_rik().unwrap();
        let original = DeviceIdentity::from_rik(rik);
        // The "recovered" device never saw the original identity bytes — only
        // the RIK (e.g. via a mnemonic).
        let recovered =
            DeviceIdentity::from_rik(cs_crypto::Rik::from_bytes(*original.rik.as_bytes()));
        assert_eq!(
            original.recipient_keys.kem_pq, recovered.recipient_keys.kem_pq,
            "from_rik must derive identical recipient keys"
        );

        let aad = cs_crypto::Aad {
            path: "vim/.vimrc".into(),
            version: 4,
        };
        let out = cs_crypto::seal(b"old secret", &aad, &original.recipient_keys).unwrap();
        let pt = cs_crypto::open(
            cs_crypto::OpenInput {
                header: &out.header,
                body: &out.body,
            },
            &aad,
            &recovered.recipient_secrets,
        )
        .unwrap();
        assert_eq!(pt, b"old secret");
    }

    #[test]
    fn new_identity_keys_match_derivation() {
        let id = DeviceIdentity::new().unwrap();
        let (pk, _) = cs_crypto::derive_recipient_keypair(&id.rik);
        assert_eq!(id.recipient_keys.kem_pq, pk.kem_pq);
        assert_eq!(id.recipient_keys.kem_classic, pk.kem_classic);
    }

    #[test]
    fn reloaded_identity_can_still_decrypt() {
        // After a store/load cycle, the device must still be able to open files
        // sealed to its public key.
        let store = InMemoryStore::new();
        let id = DeviceIdentity::new().unwrap();
        let pk = id.recipient_keys.kem_pq.clone();
        store_identity(&store, &id).unwrap();
        let loaded = load_identity(&store).unwrap();
        assert_eq!(loaded.recipient_keys.kem_pq, pk);

        let aad = cs_crypto::Aad {
            path: "after-reload".into(),
            version: 1,
        };
        let out = cs_crypto::seal(b"persisted", &aad, &loaded.recipient_keys).unwrap();
        let pt = cs_crypto::open(
            cs_crypto::OpenInput {
                header: &out.header,
                body: &out.body,
            },
            &aad,
            &loaded.recipient_secrets,
        )
        .unwrap();
        assert_eq!(pt, b"persisted");
    }
}
