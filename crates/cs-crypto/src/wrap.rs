//! Key wrapping: encrypt a 32-byte key under a 32-byte key-encryption key
//! (KEK) using XChaCha20-Poly1305. The AAD (path + version) is authenticated
//! so a wrapped key cannot be replayed against a different file or version.

use crate::aad::Aad;
use crate::error::CryptoError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedKey {
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

fn cipher(kek: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(kek))
}

fn random_nonce() -> Result<[u8; 24], CryptoError> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Encode("RNG failure".into()))?;
    Ok(nonce)
}

pub fn wrap_key(key: &[u8; 32], kek: &[u8; 32], aad: &Aad) -> Result<WrappedKey, CryptoError> {
    let c = cipher(kek);
    let nonce_bytes = random_nonce()?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad_bytes = aad.encode();
    let ct = c
        .encrypt(
            nonce,
            Payload {
                msg: key,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(WrappedKey {
        nonce: nonce_bytes,
        ct,
    })
}

pub fn unwrap_key(
    wrapped: &WrappedKey,
    kek: &[u8; 32],
    aad: &Aad,
) -> Result<[u8; 32], CryptoError> {
    let c = cipher(kek);
    let nonce = XNonce::from_slice(&wrapped.nonce);
    let aad_bytes = aad.encode();
    let pt = zeroize::Zeroizing::new(
        c.decrypt(
            nonce,
            Payload {
                msg: &wrapped.ct,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?,
    );
    if pt.len() != 32 {
        return Err(CryptoError::KeyLength);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Aad;

    #[test]
    fn wrap_unwrap_round_trips() {
        let dek = [9u8; 32];
        let kek = [1u8; 32];
        let aad = Aad {
            path: "p".into(),
            version: 1,
        };
        let w = wrap_key(&dek, &kek, &aad).unwrap();
        let got = unwrap_key(&w, &kek, &aad).unwrap();
        assert_eq!(got, dek);
    }

    #[test]
    fn unwrap_with_wrong_kek_fails() {
        let dek = [9u8; 32];
        let kek = [1u8; 32];
        let wrong = [2u8; 32];
        let aad = Aad {
            path: "p".into(),
            version: 1,
        };
        let w = wrap_key(&dek, &kek, &aad).unwrap();
        assert!(unwrap_key(&w, &wrong, &aad).is_err());
    }

    #[test]
    fn unwrap_with_wrong_aad_fails() {
        let dek = [9u8; 32];
        let kek = [1u8; 32];
        let aad1 = Aad {
            path: "p".into(),
            version: 1,
        };
        let aad2 = Aad {
            path: "p".into(),
            version: 2,
        };
        let w = wrap_key(&dek, &kek, &aad1).unwrap();
        assert!(unwrap_key(&w, &kek, &aad2).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dek = [9u8; 32];
        let kek = [1u8; 32];
        let aad = Aad {
            path: "p".into(),
            version: 1,
        };
        let mut w = wrap_key(&dek, &kek, &aad).unwrap();
        if let Some(b) = w.ct.last_mut() {
            *b ^= 0xff;
        }
        assert!(unwrap_key(&w, &kek, &aad).is_err());
    }
}
