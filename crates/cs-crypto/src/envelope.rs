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
use sha2::{Digest, Sha256 as Sha256Hasher};

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

/// Wire-format bounds for the header body. ML-KEM-768 ciphertexts are exactly
/// 1088 bytes and the wrapped DEK ciphertext is exactly 32 + 16 bytes, but a
/// little slack keeps the parser decoupled from exact constant sizes.
const MAX_PQ_CT_LEN: usize = 4096;
const MAX_WRAPPED_CT_LEN: usize = 256;

/// Read a LEB128 varint (postcard's length prefix encoding), rejecting values
/// that are malformed or absurdly large for the remaining input.
fn read_varint(buf: &[u8], pos: &mut usize, max: usize) -> Result<usize, CryptoError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err(CryptoError::Truncated);
        }
        if shift >= 64 {
            return Err(CryptoError::Truncated);
        }
        let b = buf[*pos];
        *pos += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    if value > max as u64 || value > (buf.len() - *pos) as u64 {
        return Err(CryptoError::Truncated);
    }
    Ok(value as usize)
}

/// Decode a `HeaderBody` from the exact wire format `postcard::to_allocvec`
/// produces for it (varint-prefixed Vec fields, fixed-size arrays). Unlike a
/// serde deserialize, every length is bounds-checked against the remaining
/// input BEFORE any allocation, so a hostile header cannot request a
/// multi-gigabyte `Vec::with_capacity` before authentication.
fn parse_header_body(buf: &[u8]) -> Result<HeaderBody, CryptoError> {
    let mut pos = 0;
    let pq_len = read_varint(buf, &mut pos, MAX_PQ_CT_LEN)?;
    let pq_ct = buf[pos..pos + pq_len].to_vec();
    pos += pq_len;
    if buf.len() < pos + 32 {
        return Err(CryptoError::Truncated);
    }
    let mut classic_eph = [0u8; 32];
    classic_eph.copy_from_slice(&buf[pos..pos + 32]);
    pos += 32;
    // WrappedKey { nonce: [u8; 24], ct: Vec<u8> }
    if buf.len() < pos + 24 {
        return Err(CryptoError::Truncated);
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&buf[pos..pos + 24]);
    pos += 24;
    let ct_len = read_varint(buf, &mut pos, MAX_WRAPPED_CT_LEN)?;
    let ct = buf[pos..pos + ct_len].to_vec();
    pos += ct_len;
    if pos != buf.len() {
        return Err(CryptoError::Truncated);
    }
    Ok(HeaderBody {
        pq_ct,
        classic_eph,
        wrapped_dek: WrappedKey { nonce, ct },
    })
}

fn random_nonce24() -> Result<[u8; 24], CryptoError> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Encode("RNG failure".into()))?;
    Ok(nonce)
}

pub fn seal(plaintext: &[u8], aad: &Aad, recip: &RecipientKeys) -> Result<SealOutput, CryptoError> {
    let dek = generate_dek()?;
    let (kek_raw, ct) = hybrid_encapsulate(recip)?;
    let kek = zeroize::Zeroizing::new(kek_raw);
    let wrapped_dek = wrap_key(dek.as_bytes(), &kek, aad)?;

    let hb = HeaderBody {
        pq_ct: ct.pq_ct,
        classic_eph: ct.classic_eph,
        wrapped_dek,
    };
    // ML-KEM-768 ct (~1088) + X25519 eph (32) + wrapped DEK (~72) + magic (7).
    let mut header = Vec::with_capacity(1200);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    let encoded = postcard::to_allocvec(&hb).map_err(|e| CryptoError::Encode(e.to_string()))?;
    header.extend_from_slice(&encoded);

    // Bind the header into the body AAD to prevent header/body splicing
    // attacks. The header hash ensures the body can only be decrypted with
    // the exact header it was sealed with.
    let header_hash = {
        let mut h = Sha256Hasher::new();
        h.update(&header);
        h.finalize()
    };
    let mut body_aad = aad.encode();
    body_aad.extend_from_slice(&header_hash);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(dek.as_bytes()));
    let nonce_bytes = random_nonce24()?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct_body = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &body_aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;

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
    let hb: HeaderBody = parse_header_body(&input.header[7..])?;
    if input.body.len() < 24 {
        return Err(CryptoError::Truncated);
    }
    let nonce_bytes: &[u8; 24] = input.body[..24].try_into().unwrap();
    let ct_body = &input.body[24..];

    let kem_ct = HybridKemCt {
        pq_ct: hb.pq_ct,
        classic_eph: hb.classic_eph,
    };
    let kek = zeroize::Zeroizing::new(hybrid_decapsulate(&kem_ct, secrets)?);
    let dek = zeroize::Zeroizing::new(unwrap_key(&hb.wrapped_dek, &kek, aad)?);

    // Reconstruct the same header-bound AAD used during sealing.
    let header_hash = {
        let mut h = Sha256Hasher::new();
        h.update(input.header);
        h.finalize()
    };
    let mut body_aad = aad.encode();
    body_aad.extend_from_slice(&header_hash);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*dek));
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct_body,
                aad: &body_aad,
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

    #[test]
    fn manual_parser_matches_postcard_wire_format() {
        // The bounded parser must decode exactly what postcard encodes.
        let hb = HeaderBody {
            pq_ct: vec![7u8; 1088],
            classic_eph: [9u8; 32],
            wrapped_dek: WrappedKey {
                nonce: [1u8; 24],
                ct: vec![5u8; 48],
            },
        };
        let encoded = postcard::to_allocvec(&hb).unwrap();
        let parsed = parse_header_body(&encoded).unwrap();
        assert_eq!(parsed.pq_ct, hb.pq_ct);
        assert_eq!(parsed.classic_eph, hb.classic_eph);
        assert_eq!(parsed.wrapped_dek.nonce, hb.wrapped_dek.nonce);
        assert_eq!(parsed.wrapped_dek.ct, hb.wrapped_dek.ct);
    }

    #[test]
    fn hostile_length_prefixes_do_not_allocate() {
        // varint claiming a u64::MAX-sized pq_ct in a tiny buffer must fail
        // fast without attempting the allocation.
        let hostile = {
            let mut b = vec![0xff; 10]; // all-continuation bytes then terminator
            b[9] = 0x01;
            b
        };
        assert!(matches!(
            parse_header_body(&hostile),
            Err(CryptoError::Truncated)
        ));
        // Valid varint but larger than the remaining input.
        let mut short = vec![0x40]; // len = 64
        short.extend_from_slice(&[0u8; 4]); // only 4 bytes follow
        assert!(parse_header_body(&short).is_err());
        // Trailing garbage is rejected (matches postcard's exact-consume).
        let (pk, _) = generate_recipient_keypair();
        let (_wk, ct) = crate::kem::hybrid_encapsulate(&pk).unwrap();
        let hb = HeaderBody {
            pq_ct: ct.pq_ct,
            classic_eph: ct.classic_eph,
            wrapped_dek: WrappedKey {
                nonce: [0u8; 24],
                ct: vec![0u8; 48],
            },
        };
        let mut encoded = postcard::to_allocvec(&hb).unwrap();
        encoded.push(0x00);
        assert!(parse_header_body(&encoded).is_err());
    }
}
