//! Smoke test that confirms the RustCrypto ML-KEM-768 binding behaves
//! correctly: a shared secret produced by encapsulate equals the one recovered
//! by decapsulate for the matching keypair, decapsulation of a foreign
//! ciphertext yields an unrelated key (implicit rejection), and key generation
//! from a fixed seed is deterministic (FIPS 203 KAT-style behavior).

use ml_kem::kem::{Decapsulate, Encapsulate, FromSeed, Kem, KeyExport};
use ml_kem::{MlKem768, Seed};

#[test]
fn mlkem768_decap_recovers_shared_secret() {
    let (dk, ek) = MlKem768::generate_keypair();
    let (ct, k_send) = ek.encapsulate();
    let k_recv = dk.decapsulate(&ct);
    assert_eq!(
        k_send.as_slice(),
        k_recv.as_slice(),
        "ML-KEM-768 decap must recover the encapsulated shared secret"
    );
}

#[test]
fn mlkem768_two_encapsulations_differ() {
    let (_dk, ek) = MlKem768::generate_keypair();
    let (_ct1, k1) = ek.encapsulate();
    let (_ct2, k2) = ek.encapsulate();
    assert_ne!(
        k1.as_slice(),
        k2.as_slice(),
        "each encapsulation is freshly random"
    );
}

#[test]
fn mlkem768_seed_keygen_is_deterministic() {
    let seed = Seed::from([7u8; 64]);
    let (dk1, ek1) = MlKem768::from_seed(&seed);
    let (dk2, ek2) = MlKem768::from_seed(&seed);
    assert_eq!(dk1.to_bytes(), dk2.to_bytes(), "seed must fix the dk");
    assert_eq!(ek1.to_bytes(), ek2.to_bytes(), "seed must fix the ek");

    // And a seed-derived keypair round-trips encapsulation.
    let (ct, k_send) = ek1.encapsulate();
    let k_recv = dk1.decapsulate(&ct);
    assert_eq!(k_send.as_slice(), k_recv.as_slice());
}

#[test]
fn mlkem768_implicit_rejection_hides_the_secret() {
    // Decapsulating a ciphertext produced for a DIFFERENT key must yield a
    // pseudorandom (implicit-rejection) key, not the original shared secret.
    let (dk_a, _ek_a) = MlKem768::generate_keypair();
    let (_dk_b, ek_b) = MlKem768::generate_keypair();
    let (ct_for_b, k_for_b) = ek_b.encapsulate();
    let k_seen_by_a = dk_a.decapsulate(&ct_for_b);
    assert_ne!(
        k_seen_by_a.as_slice(),
        k_for_b.as_slice(),
        "implicit rejection must not leak the other party's shared secret"
    );
}
