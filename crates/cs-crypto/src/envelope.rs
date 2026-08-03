//! The config-sync file envelope: a self-describing, versioned format that
//! bundles a hybrid-KEM-wrapped DEK with an XChaCha20-Poly1305-encrypted body.
//!
//! Header layout: `magic b"CSYNC1"` + `version u8` + postcard-encoded header
//! body (PQ ciphertext, classic ephemeral pubkey, wrapped DEK).
//! Body layout: `nonce[24]` + AEAD ciphertext+tag.

use crate::aad::Aad;
use crate::error::CryptoError;
use crate::kem::{
    hybrid_decapsulate, hybrid_encapsulate, HybridKemCt, RecipientKeys, RecipientSecrets,
};
use crate::keys::generate_dek;
use crate::wrap::{unwrap_key, wrap_key, WrappedKey};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 6] = b"CSYNC1";
pub const VERSION: u8 = 1;

pub struct SealOutput {
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}

pub struct OpenInput<'a> {
    pub header: &'a [u8],
    pub body: &'a [u8],
}

#[derive(Serialize, Deserialize)]
struct HeaderBody {
    pq_ct: Vec<u8>,
    classic_eph: [u8; 32],
    wrapped_dek: WrappedKey,
}

fn random_nonce24() -> Result<[u8; 24], CryptoError> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Encode("RNG failure".into()))?;
    Ok(nonce)
}

pub fn seal(plaintext: &[u8], aad: &Aad, recip: &RecipientKeys) -> Result<SealOutput, CryptoError> {
    let dek = generate_dek()?;
    let (kek, ct) = hybrid_encapsulate(recip)?;
    let wrapped_dek = wrap_key(dek.as_bytes(), &kek, aad)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(dek.as_bytes()));
    let nonce_bytes = random_nonce24()?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad_bytes = aad.encode();
    let ct_body = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;

    let hb = HeaderBody {
        pq_ct: ct.pq_ct,
        classic_eph: ct.classic_eph,
        wrapped_dek,
    };
    let mut header = Vec::with_capacity(64);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    let encoded = postcard::to_allocvec(&hb).map_err(|e| CryptoError::Encode(e.to_string()))?;
    header.extend_from_slice(&encoded);

    let mut body = Vec::with_capacity(24 + ct_body.len());
    body.extend_from_slice(&nonce_bytes);
    body.extend_from_slice(&ct_body);

    Ok(SealOutput { header, body })
}

pub fn open(
    input: OpenInput,
    aad: &Aad,
    secrets: &RecipientSecrets,
) -> Result<Vec<u8>, CryptoError> {
    if input.header.len() < 7 || &input.header[..6] != MAGIC {
        return Err(CryptoError::BadMagic);
    }
    if input.header[6] != VERSION {
        return Err(CryptoError::BadMagic);
    }
    let hb: HeaderBody =
        postcard::from_bytes(&input.header[7..]).map_err(|_| CryptoError::Truncated)?;
    if input.body.len() < 24 {
        return Err(CryptoError::Truncated);
    }
    let nonce_bytes: &[u8; 24] = input.body[..24].try_into().unwrap();
    let ct_body = &input.body[24..];

    let kem_ct = HybridKemCt {
        pq_ct: hb.pq_ct,
        classic_eph: hb.classic_eph,
    };
    let kek = hybrid_decapsulate(&kem_ct, secrets)?;
    let dek = unwrap_key(&hb.wrapped_dek, &kek, aad)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&dek));
    let nonce = XNonce::from_slice(nonce_bytes);
    let aad_bytes = aad.encode();
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct_body,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_recipient_keypair, Aad};

    #[test]
    fn seal_open_round_trips() {
        let (pk, sk) = generate_recipient_keypair();
        let aad = Aad {
            path: "~/.vimrc".into(),
            version: 3,
        };
        let out = seal(b"hello world", &aad, &pk).unwrap();
        let pt = open(
            OpenInput {
                header: &out.header,
                body: &out.body,
            },
            &aad,
            &sk,
        )
        .unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn header_has_magic_and_version() {
        let (pk, _) = generate_recipient_keypair();
        let aad = Aad {
            path: "p".into(),
            version: 1,
        };
        let out = seal(b"x", &aad, &pk).unwrap();
        assert_eq!(&out.header[..6], MAGIC);
        assert_eq!(out.header[6], VERSION);
    }

    #[test]
    fn tampered_body_fails_open() {
        let (pk, sk) = generate_recipient_keypair();
        let aad = Aad {
            path: "p".into(),
            version: 1,
        };
        let mut out = seal(b"secret", &aad, &pk).unwrap();
        if let Some(b) = out.body.last_mut() {
            *b ^= 0xff;
        }
        let r = open(
            OpenInput {
                header: &out.header,
                body: &out.body,
            },
            &aad,
            &sk,
        );
        assert!(r.is_err());
    }

    #[test]
    fn tampered_header_fails_open() {
        let (pk, sk) = generate_recipient_keypair();
        let aad = Aad {
            path: "p".into(),
            version: 1,
        };
        let mut out = seal(b"secret", &aad, &pk).unwrap();
        out.header[7] ^= 0xff; // tamper within postcard-encoded region
        let r = open(
            OpenInput {
                header: &out.header,
                body: &out.body,
            },
            &aad,
            &sk,
        );
        assert!(r.is_err());
    }

    #[test]
    fn wrong_aad_fails_open() {
        let (pk, sk) = generate_recipient_keypair();
        let aad1 = Aad {
            path: "p".into(),
            version: 1,
        };
        let aad2 = Aad {
            path: "p".into(),
            version: 2,
        };
        let out = seal(b"secret", &aad1, &pk).unwrap();
        assert!(open(
            OpenInput {
                header: &out.header,
                body: &out.body,
            },
            &aad2,
            &sk,
        )
        .is_err());
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let (pk, sk) = generate_recipient_keypair();
        let aad = Aad {
            path: "p".into(),
            version: 1,
        };
        let out = seal(b"", &aad, &pk).unwrap();
        let pt = open(
            OpenInput {
                header: &out.header,
                body: &out.body,
            },
            &aad,
            &sk,
        )
        .unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn bad_magic_fails() {
        let (_pk, sk) = generate_recipient_keypair();
        let aad = Aad {
            path: "p".into(),
            version: 1,
        };
        let bad_header = b"WRONG1\x01extra";
        let r = open(
            OpenInput {
                header: bad_header.as_slice(),
                body: &[0u8; 24],
            },
            &aad,
            &sk,
        );
        assert!(matches!(r, Err(CryptoError::BadMagic)));
    }
}
