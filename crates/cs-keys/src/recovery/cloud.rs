//! Cloud-bundle recovery: seal the RIK to a passphrase-derived KEK so the
//! bundle can be uploaded to a remote store and recovered anywhere with the
//! passphrase. The bundle stores only ciphertext; the binding constraint is
//! Argon2id-hardened passphrase strength.

use crate::error::KeysError;
use crate::recovery::{RecoveryBundle, RecoveryKind, RecoveryProvider};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy)]
pub struct CloudBundleProvider {
    pub argon_time_cost: u32,
    pub argon_mem_cost_kib: u32,
    pub argon_parallelism: u32,
}

impl CloudBundleProvider {
    pub fn new(time_cost: u32, mem_cost_kib: u32, parallelism: u32) -> Self {
        Self {
            argon_time_cost: time_cost,
            argon_mem_cost_kib: mem_cost_kib,
            argon_parallelism: parallelism,
        }
    }

    /// Conservative production defaults (64 MiB, t=3, p=4).
    pub fn production() -> Self {
        Self::new(3, 65_536, 4)
    }

    /// Fast parameters for tests only.
    pub fn fast_for_tests() -> Self {
        Self::new(1, 8_192, 1)
    }
}

impl Default for CloudBundleProvider {
    fn default() -> Self {
        Self::production()
    }
}

#[derive(Serialize, Deserialize)]
struct CloudPayload {
    salt: [u8; 16],
    nonce: [u8; 24],
    ct: Vec<u8>,
}

impl CloudBundleProvider {
    fn derive(
        pass: &str,
        salt: &[u8; 16],
        t: u32,
        m: u32,
        p: u32,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, KeysError> {
        let params =
            Params::new(m, t, p, Some(32)).map_err(|e| KeysError::Recovery(e.to_string()))?;
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = zeroize::Zeroizing::new([0u8; 32]);
        a2.hash_password_into(pass.as_bytes(), salt, out.as_mut())
            .map_err(|e| KeysError::Recovery(e.to_string()))?;
        Ok(out)
    }
}

impl CloudBundleProvider {
    pub fn seal_with_passphrase(
        &self,
        rik: &[u8; 32],
        passphrase: &str,
    ) -> Result<RecoveryBundle, KeysError> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| KeysError::Recovery(e.to_string()))?;
        let kek = Self::derive(
            passphrase,
            &salt,
            self.argon_time_cost,
            self.argon_mem_cost_kib,
            self.argon_parallelism,
        )?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*kek));
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| KeysError::Recovery(e.to_string()))?;
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: rik, aad: &[] })
            .map_err(|_| KeysError::Crypto(cs_crypto::CryptoError::AuthFailed))?;
        let bytes = postcard::to_allocvec(&CloudPayload { salt, nonce, ct })
            .map_err(|e| KeysError::Recovery(e.to_string()))?;
        Ok(RecoveryBundle {
            kind: RecoveryKind::CloudBundle,
            payload: bytes,
        })
    }

    pub fn recover_with_passphrase(
        &self,
        bundle: &RecoveryBundle,
        passphrase: &str,
    ) -> Result<[u8; 32], KeysError> {
        let p: CloudPayload = postcard::from_bytes(&bundle.payload)
            .map_err(|e| KeysError::Recovery(e.to_string()))?;
        let kek = Self::derive(
            passphrase,
            &p.salt,
            self.argon_time_cost,
            self.argon_mem_cost_kib,
            self.argon_parallelism,
        )?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*kek));
        let pt = cipher
            .decrypt(
                XNonce::from_slice(&p.nonce),
                Payload {
                    msg: &p.ct,
                    aad: &[],
                },
            )
            .map_err(|_| KeysError::Crypto(cs_crypto::CryptoError::AuthFailed))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&pt);
        Ok(out)
    }
}

impl RecoveryProvider for CloudBundleProvider {
    fn kind(&self) -> RecoveryKind {
        RecoveryKind::CloudBundle
    }

    fn seal(&self, _rik: &[u8; 32]) -> Result<RecoveryBundle, KeysError> {
        Err(KeysError::Recovery(
            "CloudBundleProvider::seal requires a passphrase; use seal_with_passphrase".into(),
        ))
    }

    fn recover(&self, _bundle: &RecoveryBundle) -> Result<[u8; 32], KeysError> {
        Err(KeysError::Recovery(
            "CloudBundleProvider::recover requires a passphrase; use recover_with_passphrase"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_with_passphrase_then_recover() {
        let p = CloudBundleProvider::fast_for_tests();
        let rik = [3u8; 32];
        let bundle = p
            .seal_with_passphrase(&rik, "correct horse battery staple")
            .unwrap();
        let got = p
            .recover_with_passphrase(&bundle, "correct horse battery staple")
            .unwrap();
        assert_eq!(got, rik);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let p = CloudBundleProvider::fast_for_tests();
        let rik = [3u8; 32];
        let bundle = p.seal_with_passphrase(&rik, "right").unwrap();
        assert!(p.recover_with_passphrase(&bundle, "wrong").is_err());
    }

    #[test]
    fn bundle_does_not_embed_passphrase_or_rlk_marker() {
        let p = CloudBundleProvider::fast_for_tests();
        let rik = [0x42u8; 32];
        let bundle = p
            .seal_with_passphrase(&rik, "secret-pass-UNIQUE-MARKER-xyz")
            .unwrap();
        let encoded = postcard::to_allocvec(&bundle).unwrap();
        // The passphrase must never appear verbatim in the bundle.
        assert!(!encoded
            .windows(b"secret-pass-UNIQUE-MARKER-xyz".len())
            .any(|w| w == b"secret-pass-UNIQUE-MARKER-xyz"));
        // A long, recognizable substring of the RIK (here, all 32 identical bytes
        // 0x42) must not appear as a contiguous run in the bundle. Single-byte
        // coincidences are not a meaningful leak, so we only check the full run.
        let mut marker = Vec::with_capacity(32);
        marker.extend_from_slice(&rik);
        assert!(!encoded.windows(32).any(|w| w == marker.as_slice()));
    }
}
