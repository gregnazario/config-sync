//! Shamir k-of-n recovery: split the RIK into `n` shares, any `k` of which
//! reconstruct it. Default is `k=2, n=3`.

use crate::error::KeysError;
use crate::recovery::{RecoveryBundle, RecoveryKind, RecoveryProvider};

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

impl RecoveryProvider for ShamirProvider {
    fn kind(&self) -> RecoveryKind {
        RecoveryKind::Shamir { k: self.k, n: self.n }
    }

    fn seal(&self, rik: &[u8; 32]) -> Result<RecoveryBundle, KeysError> {
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
        let bytes = postcard::to_allocvec(&shares).map_err(|e| KeysError::Recovery(e.to_string()))?;
        Ok(RecoveryBundle {
            kind: self.kind(),
            payload: bytes,
        })
    }

    fn recover(&self, bundle: &RecoveryBundle) -> Result<[u8; 32], KeysError> {
        let shares_bytes: Vec<Vec<u8>> =
            postcard::from_bytes(&bundle.payload).map_err(|e| KeysError::Recovery(e.to_string()))?;
        let shares: Vec<sharks::Share> = shares_bytes
            .iter()
            .filter_map(|b| sharks::Share::try_from(b.as_slice()).ok())
            .collect();
        if shares.len() < self.k as usize {
            return Err(KeysError::Recovery(format!(
                "need {} shares, have {}",
                self.k,
                shares.len()
            )));
        }
        let dealer = sharks::Sharks(self.k);
        let secret = dealer
            .recover(&shares)
            .map_err(|e| KeysError::Recovery(e.to_string()))?;
        if secret.len() != 32 {
            return Err(KeysError::Recovery("reconstructed secret not 32 bytes".into()));
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
        let bundle = p.seal(&rik).unwrap();
        let got = p.recover(&bundle).unwrap();
        assert_eq!(got, rik);
    }

    #[test]
    fn any_k_of_n_shares_recovers() {
        // Seal with 2-of-3, then rebuild the bundle using only the first 2 shares.
        let p = ShamirProvider::new(2, 3);
        let rik = [9u8; 32];
        let bundle = p.seal(&rik).unwrap();
        let mut shares: Vec<Vec<u8>> = postcard::from_bytes(&bundle.payload).unwrap();
        // Drop the last share, keep any 2.
        shares.pop();
        let reduced = RecoveryBundle {
            kind: bundle.kind.clone(),
            payload: postcard::to_allocvec(&shares).unwrap(),
        };
        assert_eq!(p.recover(&reduced).unwrap(), rik);
    }

    #[test]
    fn fewer_than_k_shares_cannot_recover() {
        let p = ShamirProvider::new(2, 3);
        let rik = [5u8; 32];
        let bundle = p.seal(&rik).unwrap();
        let mut shares: Vec<Vec<u8>> = postcard::from_bytes(&bundle.payload).unwrap();
        // Keep only 1 share (< k).
        shares.truncate(1);
        let reduced = RecoveryBundle {
            kind: bundle.kind.clone(),
            payload: postcard::to_allocvec(&shares).unwrap(),
        };
        assert!(p.recover(&reduced).is_err());
    }

    #[test]
    fn different_thresholds_round_trip() {
        for (k, n) in [(1u8, 1u8), (2, 3), (3, 5), (5, 7)] {
            let p = ShamirProvider::new(k, n);
            let rik = [k; 32];
            let bundle = p.seal(&rik).unwrap();
            assert_eq!(p.recover(&bundle).unwrap(), rik, "k={k} n={n}");
        }
    }
}
