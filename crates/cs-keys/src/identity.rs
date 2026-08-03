//! Device identity: the long-term RIK plus the recipient keys (public + secret)
//! used to decrypt synced files on this device. The whole bundle is serialized
//! to a single blob under the `"device-identity"` account in a [`SecretStore`].

use crate::error::KeysError;
use crate::SecretStore;
use cs_crypto::{generate_recipient_keypair, generate_rik, RecipientKeys, RecipientSecrets, Rik};
use serde::{Deserialize, Serialize};

pub struct DeviceIdentity {
    pub rik: Rik,
    pub recipient_keys: RecipientKeys,
    pub recipient_secrets: RecipientSecrets,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    rik: [u8; 32],
    kem_pq_pk: Vec<u8>,
    kem_pq_sk: Vec<u8>,
    kem_classic_pk: [u8; 32],
    kem_classic_sk: [u8; 32],
}

const ACCOUNT: &str = "device-identity";

impl DeviceIdentity {
    /// Generate a fresh device identity: a new RIK and a new recipient keypair.
    pub fn new() -> Result<Self, KeysError> {
        let (pk, sk) = generate_recipient_keypair();
        Ok(Self {
            rik: generate_rik().map_err(|e| KeysError::Recovery(e.to_string()))?,
            recipient_keys: pk,
            recipient_secrets: sk,
        })
    }

    /// Build an identity from a recovered RIK, generating a fresh recipient
    /// keypair for this device. Used by the recovery flow: the RIK is the
    /// long-term secret, while each device gets its own recipient keys.
    pub fn with_rik(rik: Rik) -> Self {
        let (pk, sk) = generate_recipient_keypair();
        Self {
            rik,
            recipient_keys: pk,
            recipient_secrets: sk,
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

pub fn load_identity(store: &dyn SecretStore) -> Result<DeviceIdentity, KeysError> {
    let bytes = store.get(ACCOUNT)?;
    let s: StoredIdentity =
        postcard::from_bytes(&bytes).map_err(|e| KeysError::Recovery(e.to_string()))?;
    Ok(DeviceIdentity {
        rik: Rik::from_bytes(s.rik),
        recipient_keys: RecipientKeys {
            kem_pq: s.kem_pq_pk,
            kem_classic: s.kem_classic_pk,
        },
        recipient_secrets: RecipientSecrets {
            kem_pq: s.kem_pq_sk,
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
    let s: StoredIdentity =
        postcard::from_bytes(bytes).map_err(|e| KeysError::Recovery(e.to_string()))?;
    Ok(DeviceIdentity {
        rik: Rik::from_bytes(s.rik),
        recipient_keys: RecipientKeys {
            kem_pq: s.kem_pq_pk,
            kem_classic: s.kem_classic_pk,
        },
        recipient_secrets: RecipientSecrets {
            kem_pq: s.kem_pq_sk,
            kem_classic: s.kem_classic_sk,
        },
    })
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
