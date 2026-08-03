//! Property-based round-trip and tamper tests for the file envelope.

use cs_crypto::{generate_recipient_keypair, open, seal, Aad, OpenInput};
use proptest::prelude::*;

proptest! {
    #[test]
    fn envelope_round_trip_arbitrary(
        plaintext in prop::collection::vec(any::<u8>(), 0..64 * 1024)
    ) {
        let (pk, sk) = generate_recipient_keypair();
        let aad = Aad { path: "p".into(), version: 1 };
        let out = seal(&plaintext, &aad, &pk).expect("seal");
        let pt = open(
            OpenInput { header: &out.header, body: &out.body },
            &aad,
            &sk,
        )
        .expect("open");
        prop_assert_eq!(pt, plaintext);
    }

    #[test]
    fn tampered_body_always_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..4096),
        flip_byte in any::<u8>()
    ) {
        let (pk, sk) = generate_recipient_keypair();
        let aad = Aad { path: "p".into(), version: 1 };
        let mut out = seal(&plaintext, &aad, &pk).expect("seal");
        // flip a byte in the body (never the 24-byte nonce prefix; flip the last
        // ciphertext byte which is always past the nonce).
        let last = out.body.len() - 1;
        out.body[last] ^= flip_byte.max(1);
        let r = open(
            OpenInput { header: &out.header, body: &out.body },
            &aad,
            &sk,
        );
        prop_assert!(r.is_err(), "tampered body must fail AEAD");
    }

    #[test]
    fn aad_version_is_authenticated(
        plaintext in prop::collection::vec(any::<u8>(), 0..2048),
        v_seal in 1u64..5,
        v_open in 1u64..5,
    ) {
        let (pk, sk) = generate_recipient_keypair();
        let seal_aad = Aad { path: "p".into(), version: v_seal };
        let open_aad = Aad { path: "p".into(), version: v_open };
        let out = seal(&plaintext, &seal_aad, &pk).expect("seal");
        let r = open(
            OpenInput { header: &out.header, body: &out.body },
            &open_aad,
            &sk,
        );
        if v_seal == v_open {
            prop_assert_eq!(r.expect("open"), plaintext);
        } else {
            prop_assert!(r.is_err(), "mismatched AAD version must fail");
        }
    }
}
