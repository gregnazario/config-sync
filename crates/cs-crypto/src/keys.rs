use zeroize::Zeroize;

macro_rules! secret_key {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Zeroize)]
        #[repr(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn from_bytes(b: [u8; 32]) -> Self {
                Self(b)
            }
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            pub fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                // constant-time-ish comparison via fixed_eq
                fixed_eq(&self.0, &other.0)
            }
        }
        impl Eq for $name {}

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name)).field(&"[secret; 32 bytes]").finish()
            }
        }
    };
}

secret_key!(Rik, "Root identity key: the user's long-term identity secret.");
secret_key!(Mk, "Master key: per-vault key that wraps each file's DEK.");
secret_key!(Dek, "Data encryption key: per-file, used by the AEAD.");

fn fixed_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generate a fresh random 32-byte secret using the OS CSPRNG.
fn random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS RNG failure");
    buf
}

pub fn generate_rik() -> Rik {
    Rik(random_32())
}
pub fn generate_mk() -> Mk {
    Mk(random_32())
}
pub fn generate_dek() -> Dek {
    Dek(random_32())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_distinct() {
        let a = generate_dek();
        let b = generate_dek();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn from_bytes_round_trips() {
        let raw = [42u8; 32];
        let k = Dek::from_bytes(raw);
        assert_eq!(k.as_bytes(), &raw);
    }

    #[test]
    fn rik_mk_dek_each_generate_32_bytes() {
        assert_eq!(generate_rik().as_bytes().len(), 32);
        assert_eq!(generate_mk().as_bytes().len(), 32);
        assert_eq!(generate_dek().as_bytes().len(), 32);
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let k = Dek::from_bytes([0xaa; 32]);
        let s = format!("{:?}", k);
        assert!(!s.contains("0xaa"));
        assert!(s.contains("secret"));
    }
}
