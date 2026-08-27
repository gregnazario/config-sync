//! Hybrid key encapsulation: ML-KEM-768 (post-quantum) combined with X25519
//! (classical). The two shared secrets are concatenated and fed through
//! HKDF-SHA256 so that breaking *either* primitive still leaves the wrap key
//! secure against an attacker who lacks the corresponding private key.
//!
//! ML-KEM is the RustCrypto `ml-kem` crate (pure Rust, FIPS 203); with the
//! `zeroize` feature enabled its shared secrets and key material are wiped on
//! drop, unlike the previous `pqcrypto` binding.
//!
//! Two key-generation paths exist:
//! - [`generate_recipient_keypair`]: freshly random keys.
//! - [`derive_recipient_keypair`]: keys **deterministically derived from the
//!   RIK** (the root identity key). This is what makes recovery work: a device
//!   that recovers the RIK re-derives the same recipient keys as every other
//!   device in the vault and can therefore decrypt every existing blob.

use crate::error::CryptoError;
use crate::keys::Rik;
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, FromSeed, Kem, KeyExport};
use ml_kem::ml_kem_768;
use ml_kem::{MlKem768, Seed};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-768 encapsulation (public) key length in bytes.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length in bytes.
pub const MLKEM768_CT_LEN: usize = 1088;
/// ML-KEM-768 decapsulation key length in *seed* form (the preferred,
/// deterministic serialization used by the `ml-kem` crate).
pub const MLKEM768_DK_SEED_LEN: usize = 64;

/// A recipient's public material: an ML-KEM-768 public key and an X25519
/// public key.
pub struct RecipientKeys {
    pub kem_pq: Vec<u8>,
    pub kem_classic: [u8; 32],
}

/// A recipient's secret material: the ML-KEM-768 decapsulation key in seed
/// form (64 bytes) and the X25519 static secret (32 bytes). Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecipientSecrets {
    pub kem_pq: Vec<u8>,
    pub kem_classic: [u8; 32],
}

/// The KEM ciphertext produced by [`hybrid_encapsulate`]: the ML-KEM-768
/// ciphertext plus the X25519 ephemeral public key.
pub struct HybridKemCt {
    pub pq_ct: Vec<u8>,
    pub classic_eph: [u8; 32],
}

/// HKDF info string with explicit algorithm domain separation.
const KEM_INFO: &[u8] = b"csync/hybrid-v1/mlkem768/x25519";
/// HKDF info strings for RIK-derived subkeys (never shared with the wrap-key
/// derivation above).
const RIK_MLKEM_SEED_INFO: &[u8] = b"csync/rik-v1/mlkem768-seed";
const RIK_X25519_INFO: &[u8] = b"csync/rik-v1/x25519-static";

/// Generate a fresh long-term recipient identity (PQ + classic keypair) from
/// the OS CSPRNG.
pub fn generate_recipient_keypair() -> (RecipientKeys, RecipientSecrets) {
    let (dk, ek) = MlKem768::generate_keypair();
    let classic_sk = StaticSecret::random();
    let classic_pk = PublicKey::from(&classic_sk);
    (
        RecipientKeys {
            kem_pq: ek.to_bytes().to_vec(),
            kem_classic: classic_pk.to_bytes(),
        },
        RecipientSecrets {
            kem_pq: dk.to_bytes().to_vec(),
            kem_classic: classic_sk.to_bytes(),
        },
    )
}

/// Deterministically derive the vault's recipient keypair from the RIK. Every
/// device holding the same RIK derives byte-identical keys, which is what
/// lets a recovered device decrypt blobs sealed before it existed.
pub fn derive_recipient_keypair(rik: &Rik) -> (RecipientKeys, RecipientSecrets) {
    let hk = Hkdf::<Sha256>::new(None, rik.as_bytes());
    // The seed IS the ML-KEM private key: keep no un-wiped copy on the stack.
    let mut seed = zeroize::Zeroizing::new(Seed::default());
    hk.expand(RIK_MLKEM_SEED_INFO, seed.as_mut())
        .expect("64 <= 255");
    let (dk, ek) = MlKem768::from_seed(&seed);
    let mut classic_bytes = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(RIK_X25519_INFO, classic_bytes.as_mut())
        .expect("32 <= 255");
    let classic_sk = StaticSecret::from(*classic_bytes);
    let classic_pk = PublicKey::from(&classic_sk);
    (
        RecipientKeys {
            kem_pq: ek.to_bytes().to_vec(),
            kem_classic: classic_pk.to_bytes(),
        },
        RecipientSecrets {
            kem_pq: dk.to_bytes().to_vec(),
            kem_classic: *classic_bytes,
        },
    )
}

fn derive_wrap_key(ss_pq: &[u8], ss_classic: &[u8]) -> [u8; 32] {
    // Both shared secrets are exactly 32 bytes — use a stack array, zeroized after.
    let mut ikm = [0u8; 64];
    ikm[..ss_pq.len()].copy_from_slice(ss_pq);
    ikm[ss_pq.len()..ss_pq.len() + ss_classic.len()].copy_from_slice(ss_classic);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(KEM_INFO, &mut okm).expect("32 <= 255");
    zeroize::Zeroize::zeroize(&mut ikm);
    okm
}

/// Encapsulate a fresh 32-byte wrap key for `recip`. Returns the key together
/// with the ciphertext the recipient needs to recover it.
pub fn hybrid_encapsulate(recip: &RecipientKeys) -> Result<([u8; 32], HybridKemCt), CryptoError> {
    let ek_bytes: &[u8; MLKEM768_EK_LEN] = recip
        .kem_pq
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Kem)?;
    let ek_arr = ml_kem::kem::Key::<ml_kem_768::EncapsulationKey>::from(*ek_bytes);
    let ek = ml_kem_768::EncapsulationKey::new(&ek_arr).map_err(|_| CryptoError::Kem)?;
    let (ct, mut ss_pq) = ek.encapsulate();
    let eph_sk = StaticSecret::random();
    let eph_pk = PublicKey::from(&eph_sk);
    let classic_pk = PublicKey::from(recip.kem_classic);
    let ss_classic = eph_sk.diffie_hellman(&classic_pk);
    let wrap_key = derive_wrap_key(ss_pq.as_slice(), ss_classic.as_bytes());
    // SharedKey has no ZeroizeOnDrop: wipe it explicitly.
    ss_pq.zeroize();
    Ok((
        wrap_key,
        HybridKemCt {
            pq_ct: ct.as_slice().to_vec(),
            classic_eph: eph_pk.to_bytes(),
        },
    ))
}

/// Decapsulate the wrap key from `ct` using `secrets`. Returns `Err(Kem)` if
/// the ciphertext bytes are malformed. Note: ML-KEM decapsulation always
/// returns *a* shared secret even for a wrong ciphertext (it is FO-validated
/// to a pseudorandom value), so a wrong private key yields a wrong — but
/// present — wrap key; downstream AEAD authentication then catches the
/// mismatch.
pub fn hybrid_decapsulate(
    ct: &HybridKemCt,
    secrets: &RecipientSecrets,
) -> Result<[u8; 32], CryptoError> {
    let ct_bytes: &[u8; MLKEM768_CT_LEN] = ct
        .pq_ct
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Kem)?;
    let kem_ct = ml_kem_768::Ciphertext::from(*ct_bytes);
    let dk = dk_from_secrets(secrets)?;
    let mut ss_pq = dk.decapsulate(&kem_ct);
    let classic_sk = StaticSecret::from(secrets.kem_classic);
    let eph_pk = PublicKey::from(ct.classic_eph);
    let ss_classic = classic_sk.diffie_hellman(&eph_pk);
    let wrap_key = derive_wrap_key(ss_pq.as_slice(), ss_classic.as_bytes());
    // SharedKey has no ZeroizeOnDrop: wipe it explicitly.
    ss_pq.zeroize();
    Ok(wrap_key)
}

/// Rebuild the ML-KEM decapsulation key from the stored seed-form bytes.
fn dk_from_secrets(
    secrets: &RecipientSecrets,
) -> Result<ml_kem_768::DecapsulationKey, CryptoError> {
    let seed_bytes: &[u8; MLKEM768_DK_SEED_LEN] = secrets
        .kem_pq
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Kem)?;
    let mut seed = zeroize::Zeroizing::new(Seed::default());
    seed.copy_from_slice(seed_bytes);
    Ok(MlKem768::from_seed(&seed).0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_rik;

    #[test]
    fn encapsulate_decapsulate_round_trips() {
        let (pk, sk) = generate_recipient_keypair();
        let (wk1, ct) = hybrid_encapsulate(&pk).unwrap();
        let wk2 = hybrid_decapsulate(&ct, &sk).expect("decap");
        assert_eq!(wk1, wk2, "matching private key must recover the wrap key");
    }

    #[test]
    fn decap_with_wrong_private_key_yields_different_wrap_key() {
        // ML-KEM decap always returns a value, but with the wrong sk it will not
        // match what encapsulate produced. Verify the recovered wrap keys differ.
        let (pk_b, sk_b) = generate_recipient_keypair();
        let (_pk_c, sk_c) = generate_recipient_keypair();

        // Encapsulate to pk_b, recover correctly with sk_b.
        let (wk_correct, ct) = hybrid_encapsulate(&pk_b).unwrap();
        let wk_match = hybrid_decapsulate(&ct, &sk_b).unwrap();
        assert_eq!(wk_correct, wk_match);

        // Recover with the wrong sk_c -> different wrap key.
        let wk_wrong = hybrid_decapsulate(&ct, &sk_c).unwrap();
        assert_ne!(
            wk_wrong, wk_match,
            "wrong private key must yield a different wrap key"
        );
    }

    #[test]
    fn two_encapsulations_produce_distinct_keys() {
        let (pk, _sk) = generate_recipient_keypair();
        let (wk1, _ct1) = hybrid_encapsulate(&pk).unwrap();
        let (wk2, _ct2) = hybrid_encapsulate(&pk).unwrap();
        assert_ne!(wk1, wk2, "each encapsulation is freshly random");
    }

    #[test]
    fn malformed_pq_ciphertext_errors() {
        let (_pk, sk) = generate_recipient_keypair();
        let bad_ct = HybridKemCt {
            pq_ct: vec![0u8; 10], // wrong length
            classic_eph: [0u8; 32],
        };
        assert!(matches!(
            hybrid_decapsulate(&bad_ct, &sk),
            Err(CryptoError::Kem)
        ));
    }

    #[test]
    fn rik_derivation_is_deterministic_and_distinct_per_rik() {
        let rik1 = generate_rik().unwrap();
        let rik2 = generate_rik().unwrap();

        let (pk_a, sk_a) = derive_recipient_keypair(&rik1);
        let (pk_b, sk_b) = derive_recipient_keypair(&rik1);
        assert_eq!(pk_a.kem_pq, pk_b.kem_pq, "same RIK must derive same keys");
        assert_eq!(pk_a.kem_classic, pk_b.kem_classic);
        assert_eq!(sk_a.kem_pq, sk_b.kem_pq);
        assert_eq!(sk_a.kem_classic, sk_b.kem_classic);

        let (pk_c, _sk_c) = derive_recipient_keypair(&rik2);
        assert_ne!(
            pk_a.kem_pq, pk_c.kem_pq,
            "different RIKs derive different keys"
        );
        assert_ne!(pk_a.kem_classic, pk_c.kem_classic);
    }

    #[test]
    fn rik_derived_keys_can_seal_and_open() {
        let rik = generate_rik().unwrap();
        let (pk, sk) = derive_recipient_keypair(&rik);
        let (wk, ct) = hybrid_encapsulate(&pk).unwrap();
        assert_eq!(hybrid_decapsulate(&ct, &sk).unwrap(), wk);
    }
}
