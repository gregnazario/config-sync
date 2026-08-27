//! Manifest signing: an Ed25519 key pair deterministically derived from the
//! RIK, used to sign the sealed sync manifest before it is written to
//! untrusted storage.
//!
//! The AEAD envelope already gives the manifest confidentiality and integrity
//! against a store that lacks the vault's keys. The signature adds two things
//! the envelope alone cannot:
//! - the version and seal-time are carried *outside* the ciphertext yet are
//!   unforgeable, so every device (even one with no prior history) can reject
//!   rolled-back or stale manifests without decrypting first;
//! - authenticity is bound to the RIK itself rather than to a single device's
//!   recipient key material.

use crate::keys::Rik;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;

/// Ed25519 signature length in bytes.
pub const MANIFEST_SIG_LEN: usize = 64;
/// Ed25519 verifying (public) key length in bytes.
pub const MANIFEST_VERIFYING_KEY_LEN: usize = 32;

/// HKDF info string for the manifest-signing subkey (domain-separated from
/// every other RIK derivation).
const RIK_SIGNING_INFO: &[u8] = b"csync/rik-v1/manifest-signing";

/// The vault's manifest signing key. All devices derive the identical key
/// from the RIK, so any device can verify and (re)sign manifests.
pub struct ManifestSigningKey {
    signing: SigningKey,
}

impl ManifestSigningKey {
    /// Deterministically derive the signing key from the RIK.
    pub fn derive_from_rik(rik: &Rik) -> Self {
        let hk = Hkdf::<Sha256>::new(None, rik.as_bytes());
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        hk.expand(RIK_SIGNING_INFO, seed.as_mut())
            .expect("32 <= 255");
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The Ed25519 verifying key bytes (safe to share; derived from the RIK
    /// but not secret).
    pub fn verifying_key_bytes(&self) -> [u8; MANIFEST_VERIFYING_KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign `msg`, returning the raw 64-byte Ed25519 signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; MANIFEST_SIG_LEN] {
        self.signing.sign(msg).to_bytes()
    }
}

/// Verify a manifest signature. Returns `false` on any mismatch (or on
/// malformed keys); never panics on hostile input.
pub fn verify_manifest_signature(
    verifying_key: &[u8; MANIFEST_VERIFYING_KEY_LEN],
    msg: &[u8],
    signature: &[u8; MANIFEST_SIG_LEN],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(verifying_key) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(signature)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_rik;

    #[test]
    fn derivation_is_deterministic_and_rik_bound() {
        let rik1 = generate_rik().unwrap();
        let rik2 = generate_rik().unwrap();
        let k1 = ManifestSigningKey::derive_from_rik(&rik1);
        let k1b = ManifestSigningKey::derive_from_rik(&rik1);
        let k2 = ManifestSigningKey::derive_from_rik(&rik2);
        assert_eq!(k1.verifying_key_bytes(), k1b.verifying_key_bytes());
        assert_ne!(k1.verifying_key_bytes(), k2.verifying_key_bytes());
    }

    #[test]
    fn sign_verify_round_trip_and_tamper_detection() {
        let k = ManifestSigningKey::derive_from_rik(&generate_rik().unwrap());
        let msg = b"some manifest bytes";
        let sig = k.sign(msg);
        assert!(verify_manifest_signature(
            &k.verifying_key_bytes(),
            msg,
            &sig
        ));

        // Tampered message fails.
        assert!(!verify_manifest_signature(
            &k.verifying_key_bytes(),
            b"some manifest bytes!",
            &sig
        ));
        // Tampered signature fails.
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!verify_manifest_signature(
            &k.verifying_key_bytes(),
            msg,
            &bad
        ));
        // Wrong key fails.
        let other = ManifestSigningKey::derive_from_rik(&generate_rik().unwrap());
        assert!(!verify_manifest_signature(
            &other.verifying_key_bytes(),
            msg,
            &sig
        ));
    }
}
