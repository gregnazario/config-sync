//! Smoke test that confirms the liboqs ML-KEM-768 binding behaves correctly:
//! a shared secret produced by encapsulate equals the one recovered by
//! decapsulate for the matching keypair. This catches a misconfigured or
//! broken liboqs build.

use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::SharedSecret as _;

#[test]
fn mlkem768_decap_recovers_shared_secret() {
    let (pk, sk) = mlkem768::keypair();
    let (ss_enc, ct) = mlkem768::encapsulate(&pk);
    let ss_dec = mlkem768::decapsulate(&ct, &sk);
    assert_eq!(
        ss_enc.as_bytes(),
        ss_dec.as_bytes(),
        "ML-KEM-768 decap must recover the encapsulated shared secret"
    );
}

#[test]
fn mlkem768_two_encapsulations_differ() {
    let (pk, _sk) = mlkem768::keypair();
    let (ss1, _) = mlkem768::encapsulate(&pk);
    let (ss2, _) = mlkem768::encapsulate(&pk);
    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "each encapsulation is freshly random"
    );
}
