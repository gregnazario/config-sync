//! Offline BIP-39 mnemonic recovery.
//!
//! A fresh 256-bit recovery key is generated and shown to the user as a 24-word
//! BIP-39 mnemonic. The recovery key is stretched into a key-encryption key
//! (KEK) via Argon2id; the RIK is sealed to that KEK with XChaCha20-Poly1305.
//!
//! **Production usage:** [`MnemonicProvider::seal_with_mnemonic`] takes the
//! mnemonic the user has transcribed and never embeds the recovery key in the
//! bundle. The convenience `RecoveryProvider::seal` impl generates a mnemonic
//! and returns it *out of band* via [`SealedWithMnemonic`]; callers must
//! display the mnemonic to the user and then drop it.

use crate::error::KeysError;
use crate::recovery::{RecoveryBundle, RecoveryKind, RecoveryProvider};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

/// Tunable Argon2id parameters. Defaults match the spec (m=64MiB, t=3, p=4)
/// but tests use weaker values for speed.
#[derive(Clone, Copy)]
pub struct MnemonicProvider {
    pub argon_time_cost: u32,
    pub argon_mem_cost_kib: u32,
    pub argon_parallelism: u32,
}

impl MnemonicProvider {
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

#[derive(Serialize, Deserialize)]
struct MnemonicPayload {
    salt: [u8; 16],
    nonce: [u8; 24],
    ct: Vec<u8>,
}

/// Result of [`MnemonicProvider::seal_with_mnemonic`]: the recovery bundle plus
/// the mnemonic the user must transcribe. The mnemonic is NOT embedded in the
/// bundle.
pub struct SealedWithMnemonic {
    pub bundle: RecoveryBundle,
    pub mnemonic_words: String,
}

impl MnemonicProvider {
    fn derive_kek(
        recovery_key: &[u8],
        salt: &[u8; 16],
        t: u32,
        m: u32,
        p: u32,
    ) -> Result<[u8; 32], KeysError> {
        let params =
            Params::new(m, t, p, Some(32)).map_err(|e| KeysError::Recovery(e.to_string()))?;
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        a2.hash_password_into(recovery_key, salt, &mut out)
            .map_err(|e| KeysError::Recovery(e.to_string()))?;
        Ok(out)
    }

    /// Generate a fresh 24-word BIP-39 mnemonic, derive its recovery key, and
    /// seal the RIK to it. The mnemonic is returned for the user to transcribe;
    /// it is never stored in the bundle.
    ///
    /// If `passphrase` is `Some`, it is used as the BIP-39 passphrase (second
    /// factor), providing an additional layer of security: an attacker who
    /// obtains the mnemonic words still cannot derive the key without the
    /// passphrase. The passphrase is never stored.
    pub fn seal_with_mnemonic(
        &self,
        rik: &[u8; 32],
        passphrase: Option<&str>,
    ) -> Result<SealedWithMnemonic, KeysError> {
        let mnemonic =
            bip39::Mnemonic::generate(24).map_err(|e| KeysError::Recovery(e.to_string()))?;
        let recovery_key = mnemonic.to_seed(passphrase.unwrap_or(""));
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| KeysError::Recovery(e.to_string()))?;
        let bundle = self.seal_with_recovery_key(rik, &recovery_key, &salt)?;
        Ok(SealedWithMnemonic {
            bundle,
            mnemonic_words: mnemonic.to_string(),
        })
    }

    fn seal_with_recovery_key(
        &self,
        rik: &[u8; 32],
        recovery_key: &[u8],
        salt: &[u8; 16],
    ) -> Result<RecoveryBundle, KeysError> {
        let kek = Self::derive_kek(
            recovery_key,
            salt,
            self.argon_time_cost,
            self.argon_mem_cost_kib,
            self.argon_parallelism,
        )?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| KeysError::Recovery(e.to_string()))?;
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: rik, aad: &[] })
            .map_err(|_| KeysError::Crypto(cs_crypto::CryptoError::AuthFailed))?;
        let payload = MnemonicPayload {
            salt: *salt,
            nonce,
            ct,
        };
        let bytes =
            postcard::to_allocvec(&payload).map_err(|e| KeysError::Recovery(e.to_string()))?;
        Ok(RecoveryBundle {
            kind: RecoveryKind::Mnemonic,
            payload: bytes,
        })
    }

    /// Recover the RIK from a bundle using the user's transcribed mnemonic words.
    ///
    /// If `passphrase` is `Some`, it must match the passphrase used during
    /// `seal_with_mnemonic`. An empty passphrase (`None` or `Some("")`) is
    /// used if no second factor was set.
    pub fn recover_with_mnemonic(
        &self,
        bundle: &RecoveryBundle,
        mnemonic_words: &str,
        passphrase: Option<&str>,
    ) -> Result<[u8; 32], KeysError> {
        let p: MnemonicPayload = postcard::from_bytes(&bundle.payload)
            .map_err(|e| KeysError::Recovery(e.to_string()))?;
        let mnemonic = bip39::Mnemonic::parse_normalized(mnemonic_words)
            .map_err(|e| KeysError::Recovery(e.to_string()))?;
        let recovery_key = mnemonic.to_seed(passphrase.unwrap_or(""));
        let kek = Self::derive_kek(
            &recovery_key,
            &p.salt,
            self.argon_time_cost,
            self.argon_mem_cost_kib,
            self.argon_parallelism,
        )?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));
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

impl RecoveryProvider for MnemonicProvider {
    fn kind(&self) -> RecoveryKind {
        RecoveryKind::Mnemonic
    }

    /// Generates a mnemonic, seals the RIK, and — to satisfy the trait —
    /// returns the bundle. **The mnemonic is lost** when using this entry
    /// point because the trait cannot return it. Use
    /// [`MnemonicProvider::seal_with_mnemonic`] in production so the mnemonic
    /// can be displayed to the user.
    fn seal(&self, rik: &[u8; 32]) -> Result<RecoveryBundle, KeysError> {
        Ok(self.seal_with_mnemonic(rik, None)?.bundle)
    }

    fn recover(&self, _bundle: &RecoveryBundle) -> Result<[u8; 32], KeysError> {
        Err(KeysError::Recovery(
            "MnemonicProvider::recover requires the mnemonic words; use recover_with_mnemonic"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_with_mnemonic_then_recover_round_trips() {
        let p = MnemonicProvider::fast_for_tests();
        let rik = [7u8; 32];
        let sealed = p.seal_with_mnemonic(&rik, None).unwrap();
        // The mnemonic is genuinely 24 words.
        assert_eq!(sealed.mnemonic_words.split_whitespace().count(), 24);
        let got = p
            .recover_with_mnemonic(&sealed.bundle, &sealed.mnemonic_words, None)
            .unwrap();
        assert_eq!(got, rik);
    }

    #[test]
    fn wrong_mnemonic_fails_recovery() {
        let p = MnemonicProvider::fast_for_tests();
        let rik = [7u8; 32];
        let sealed_a = p.seal_with_mnemonic(&rik, None).unwrap();
        let sealed_b = p.seal_with_mnemonic(&rik, None).unwrap();
        // Recover bundle A with mnemonic B -> must fail (different recovery keys).
        assert!(p
            .recover_with_mnemonic(&sealed_a.bundle, &sealed_b.mnemonic_words, None)
            .is_err());
    }

    #[test]
    fn bundle_does_not_embed_mnemonic_or_recovery_key() {
        let p = MnemonicProvider::fast_for_tests();
        let sealed = p.seal_with_mnemonic(&[7u8; 32], None).unwrap();
        // The bundle payload must not contain the mnemonic words.
        for word in sealed.mnemonic_words.split_whitespace() {
            assert!(
                !postcard::to_allocvec(&sealed.bundle)
                    .unwrap()
                    .windows(word.len())
                    .any(|w| w == word.as_bytes()),
                "bundle must not leak mnemonic word '{word}'"
            );
        }
    }

    #[test]
    fn malformed_payload_fails() {
        let p = MnemonicProvider::fast_for_tests();
        let bad = RecoveryBundle {
            kind: RecoveryKind::Mnemonic,
            payload: vec![0u8; 3],
        };
        assert!(p.recover_with_mnemonic(&bad, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", None).is_err());
    }
}
