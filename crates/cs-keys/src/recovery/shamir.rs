//! Shamir k-of-n recovery: split the RIK into `n` shares, any `k` of which
//! reconstruct it. Default is `k=2, n=3`.
//!
//! Shares are returned as **separate blobs** (one per share) so they can be
//! distributed to independent holders/locations. Each share is a standalone
//! `RecoveryBundle`. This preserves the threshold model: compromising fewer
//! than `k` share-holders reveals nothing about the secret.

use crate::error::KeysError;
use crate::recovery::{RecoveryBundle, RecoveryKind, RecoveryProvider};
use std::collections::BTreeSet;

pub struct ShamirProvider {
    pub k: u8,
    pub n: u8,
}

impl ShamirProvider {
    pub fn new(k: u8, n: u8) -> Self {
        Self { k, n }
    }
}

impl Default for ShamirProvider {
    fn default() -> Self {
        Self::new(2, 3)
    }
}

/// A single Shamir share with its index, suitable for independent storage.
#[derive(Clone, Debug)]
pub struct ShamirShare {
    pub index: u8,
    pub data: Vec<u8>,
}

/// The output of splitting a secret: `n` independent shares, any `k` of which
/// can reconstruct it. Each share should be stored in a **different location**
/// (different cloud providers, different physical devices, etc.).
pub struct SplitShares {
    pub threshold: u8,
    pub shares: Vec<ShamirShare>,
}

impl ShamirProvider {
    /// Split a secret into `n` independent shares. Returns each share separately
    /// so the caller can distribute them to independent holders/locations.
    ///
    /// **Security:** Each share MUST be stored in a different location. Storing
    /// all shares together defeats the threshold model entirely.
    pub fn split(&self, secret: &[u8; 32]) -> Result<SplitShares, KeysError> {
        let dealer = sharks::Sharks(self.k);
        let shares: Vec<ShamirShare> = dealer
            .dealer(secret)
            .take(self.n.into())
            .map(|s| {
                let bytes: Vec<u8> = (&s).into();
                let index = bytes.first().copied().unwrap_or(0);
                ShamirShare { index, data: bytes }
            })
            .collect();
        if shares.len() != self.n as usize {
            return Err(KeysError::Recovery(format!(
                "expected {} shares, got {}",
                self.n,
                shares.len()
            )));
        }
        Ok(SplitShares {
            threshold: self.k,
            shares,
        })
    }

    /// Reconstruct the secret from `k` or more shares. Shares can be provided
    /// in any order and from any subset of holders.
    pub fn recombine(&self, shares: &[ShamirShare]) -> Result<[u8; 32], KeysError> {
        // Reject any duplicates outright — supplying the same share twice
        // produces a silently wrong reconstruction via GF256 div-by-zero.
        let mut seen: BTreeSet<u8> = BTreeSet::new();
        for s in shares {
            if !seen.insert(s.index) {
                return Err(KeysError::Recovery(
                    "duplicate shares are not allowed; supply each distinct share once".into(),
                ));
            }
        }
        if (seen.len() as u8) < self.k {
            return Err(KeysError::Recovery(format!(
                "need {} distinct shares, have {}",
                self.k,
                seen.len()
            )));
        }
        let dealer = sharks::Sharks(self.k);
        let parsed: Vec<sharks::Share> = shares
            .iter()
            .filter_map(|s| sharks::Share::try_from(s.data.as_slice()).ok())
            .collect();
        let secret = dealer
            .recover(&parsed)
            .map_err(|_| KeysError::Recovery("reconstruct failed".into()))?;
        if secret.len() != 32 {
            return Err(KeysError::Recovery(
                "reconstructed secret not 32 bytes".into(),
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&secret);
        Ok(out)
    }
}

// The RecoveryProvider trait implementation stores ALL shares in one bundle.
// This is provided for backward compatibility with the trait, but callers who
// want real threshold security should use `split()` + `recombine()` directly
// and distribute shares to separate storage locations.
impl RecoveryProvider for ShamirProvider {
    fn kind(&self) -> RecoveryKind {
        RecoveryKind::Shamir {
            k: self.k,
            n: self.n,
        }
    }

    fn seal(&self, rik: &[u8; 32]) -> Result<RecoveryBundle, KeysError> {
        // ⚠️ Stores all shares in one bundle. For real threshold security,
        // use split() and store each share separately.
        let dealer = sharks::Sharks(self.k);
        let shares: Vec<Vec<u8>> = dealer
            .dealer(rik)
            .take(self.n.into())
            .map(|s| Vec::<u8>::from(&s))
            .collect();
        if shares.len() != self.n as usize {
            return Err(KeysError::Recovery(format!(
                "expected {} shares, got {}",
                self.n,
                shares.len()
            )));
        }
        let bytes =
            postcard::to_allocvec(&shares).map_err(|e| KeysError::Recovery(e.to_string()))?;
        Ok(RecoveryBundle {
            kind: self.kind(),
            payload: bytes,
        })
    }

    fn recover(&self, bundle: &RecoveryBundle) -> Result<[u8; 32], KeysError> {
        let shares_bytes: Vec<Vec<u8>> = postcard::from_bytes(&bundle.payload)
            .map_err(|e| KeysError::Recovery(e.to_string()))?;
        // Validate that shares are distinct by x-coordinate.
        let parsed: Vec<sharks::Share> = shares_bytes
            .iter()
            .filter_map(|b| sharks::Share::try_from(b.as_slice()).ok())
            .collect();
        let x_coords: BTreeSet<u8> = parsed.iter().map(|s| s.x.0).collect();
        if (x_coords.len() as u8) < self.k {
            return Err(KeysError::Recovery(format!(
                "need {} distinct shares, have {}",
                self.k,
                x_coords.len()
            )));
        }
        let dealer = sharks::Sharks(self.k);
        let secret = dealer
            .recover(&parsed)
            .map_err(|_| KeysError::Recovery("reconstruct failed".into()))?;
        if secret.len() != 32 {
            return Err(KeysError::Recovery(
                "reconstructed secret not 32 bytes".into(),
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&secret);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_recombine_with_all_shares() {
        let p = ShamirProvider::default();
        let rik = [5u8; 32];
        let split = p.split(&rik).unwrap();
        assert_eq!(split.shares.len(), 3);
        let got = p.recombine(&split.shares).unwrap();
        assert_eq!(got, rik);
    }

    #[test]
    fn any_k_of_n_shares_recovers() {
        let p = ShamirProvider::new(2, 3);
        let rik = [9u8; 32];
        let split = p.split(&rik).unwrap();
        // Drop the last share, keep any 2.
        let mut reduced = split.shares.clone();
        reduced.pop();
        assert_eq!(p.recombine(&reduced).unwrap(), rik);
    }

    #[test]
    fn fewer_than_k_shares_cannot_recover() {
        let p = ShamirProvider::new(2, 3);
        let rik = [5u8; 32];
        let split = p.split(&rik).unwrap();
        let mut reduced = split.shares.clone();
        reduced.truncate(1);
        assert!(p.recombine(&reduced).is_err());
    }

    #[test]
    fn duplicate_shares_do_not_count_toward_threshold() {
        let p = ShamirProvider::new(2, 3);
        let rik = [5u8; 32];
        let split = p.split(&rik).unwrap();
        // Use the same share twice — should fail (needs 2 *distinct* shares).
        let dup = vec![split.shares[0].clone(), split.shares[0].clone()];
        assert!(p.recombine(&dup).is_err());
    }

    #[test]
    fn different_thresholds_round_trip() {
        for (k, n) in [(1u8, 1u8), (2, 3), (3, 5), (5, 7)] {
            let p = ShamirProvider::new(k, n);
            let rik = [k; 32];
            let split = p.split(&rik).unwrap();
            assert_eq!(p.recombine(&split.shares).unwrap(), rik, "k={k} n={n}");
        }
    }

    #[test]
    fn trait_seal_recover_backward_compat() {
        let p = ShamirProvider::default();
        let rik = [5u8; 32];
        let bundle = p.seal(&rik).unwrap();
        assert_eq!(p.recover(&bundle).unwrap(), rik);
    }
}
