//! Hybrid key encapsulation: ML-KEM-768 (post-quantum) combined with X25519
//! (classical). The two shared secrets are concatenated and fed through
//! HKDF-SHA256 so that breaking *either* primitive still leaves the wrap key
//! secure against an attacker who lacks the corresponding private key.

use crate::error::CryptoError;
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// A recipient's public material: an ML-KEM-768 public key and an X25519
/// public key.
pub struct RecipientKeys {
    pub kem_pq: Vec<u8>,
    pub kem_classic: [u8; 32],
}

/// A recipient's secret material: an ML-KEM-768 secret key and an X25519
/// static secret (32 bytes).
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

const KEM_INFO: &[u8] = b"csync/hybrid-v1";

/// Generate a fresh long-term recipient identity (PQ + classic keypair).
pub fn generate_recipient_keypair() -> (RecipientKeys, RecipientSecrets) {
    let (pq_pk, pq_sk) = mlkem768::keypair();
    let classic_sk = StaticSecret::random();
    let classic_pk = PublicKey::from(&classic_sk);
    (
        RecipientKeys {
            kem_pq: pq_pk.as_bytes().to_vec(),
            kem_classic: classic_pk.to_bytes(),
        },
        RecipientSecrets {
            kem_pq: pq_sk.as_bytes().to_vec(),
            kem_classic: classic_sk.to_bytes(),
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
    let pq_pk = mlkem768::PublicKey::from_bytes(&recip.kem_pq).map_err(|_| CryptoError::Kem)?;
    let (ss_pq, pq_ct) = mlkem768::encapsulate(&pq_pk);
    let eph_sk = StaticSecret::random();
    let eph_pk = PublicKey::from(&eph_sk);
    let classic_pk = PublicKey::from(recip.kem_classic);
    let ss_classic = eph_sk.diffie_hellman(&classic_pk);
    let wrap_key = derive_wrap_key(ss_pq.as_bytes(), ss_classic.as_bytes());
    Ok((
        wrap_key,
        HybridKemCt {
            pq_ct: pq_ct.as_bytes().to_vec(),
            classic_eph: eph_pk.to_bytes(),
        },
    ))
}

/// Decapsulate the wrap key from `ct` using `secrets`. Returns `Err(Kem)` if
/// the ciphertext bytes are malformed. Note: ML-KEM decapsulation always
/// returns *a* shared secret even for a wrong ciphertext (it is FO-validated
/// to a random value), so a wrong private key yields a wrong — but present —
/// wrap key; downstream AEAD authentication then catches the mismatch.
pub fn hybrid_decapsulate(
    ct: &HybridKemCt,
    secrets: &RecipientSecrets,
) -> Result<[u8; 32], CryptoError> {
    let pq_ct = mlkem768::Ciphertext::from_bytes(&ct.pq_ct).map_err(|_| CryptoError::Kem)?;
    let pq_sk = mlkem768::SecretKey::from_bytes(&secrets.kem_pq).map_err(|_| CryptoError::Kem)?;
    let ss_pq = mlkem768::decapsulate(&pq_ct, &pq_sk);
    let classic_sk = StaticSecret::from(secrets.kem_classic);
    let eph_pk = PublicKey::from(ct.classic_eph);
    let ss_classic = classic_sk.diffie_hellman(&eph_pk);
    Ok(derive_wrap_key(ss_pq.as_bytes(), ss_classic.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
