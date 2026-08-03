//! Biometric-gated secret storage.
//!
//! On macOS this stores secrets in the Keychain with a `SecAccessControl`
//! requiring **biometrics (Touch ID / Face ID) OR the device passcode** to
//! release — the OS prompts the user via the standard biometric sheet on every
//! read. On other platforms there is no standard cross-desktop biometric
//! keychain API, so the store falls back to the regular [`KeyringStore`] (and
//! `is_biometric_gated()` reports `false`) — see the platform notes below.
//!
//! This implements [`SecretStore`] just like the non-biometric stores, so the
//! rest of config-sync is unaware of the difference.

// `KeysError` and `SecretStore` are imported within the platform `imp` modules
// that actually use them; the parent only defines the struct + helpers.

/// A secret store that gates secret release behind biometrics where the
/// platform supports it.
pub struct BiometricStore {
    pub service: String,
}

impl BiometricStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// True when secret release actually requires a biometric/passcode prompt
    /// on this platform (macOS Keychain ACL / Windows Hello). False on Linux/
    /// FreeBSD where no standard cross-desktop biometric keychain API exists.
    pub fn is_biometric_gated(&self) -> bool {
        cfg!(any(target_os = "macos", target_os = "windows"))
    }
}

// ---- macOS: Keychain items with a Touch ID / passcode access control ----
#[cfg(target_os = "macos")]
mod imp {
    use super::BiometricStore;
    use crate::error::KeysError;
    use crate::SecretStore;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};

    fn biometry_flags() -> AccessControlOptions {
        // Require biometry OR device passcode; either satisfies the prompt.
        AccessControlOptions::BIOMETRY_ANY
            | AccessControlOptions::OR
            | AccessControlOptions::DEVICE_PASSCODE
    }

    impl SecretStore for BiometricStore {
        fn put(&self, account: &str, secret: &[u8]) -> Result<(), KeysError> {
            // Base64-encode so the secret survives the generic-password byte path.
            let b64 = STANDARD.encode(secret);
            let mut opts = PasswordOptions::new_generic_password(&self.service, account);
            opts.set_access_control_options(biometry_flags());
            set_generic_password_options(b64.as_bytes(), opts)
                .map_err(|e| KeysError::Keychain(format!("biometric keychain put: {e}")))
        }

        fn get(&self, account: &str) -> Result<Vec<u8>, KeysError> {
            // Reading a biometry-gated item triggers the OS biometric prompt.
            let raw = get_generic_password(&self.service, account).map_err(|e| match e.code() {
                    -25300 /* errSecItemNotFound */ => KeysError::NotFound,
                    _ => KeysError::Keychain(format!("biometric keychain get: {e}")),
                })?;
            let s = String::from_utf8(raw)
                .map_err(|e| KeysError::Keychain(format!("biometric keychain utf8: {e}")))?;
            STANDARD
                .decode(s)
                .map_err(|e| KeysError::Keychain(format!("biometric keychain b64: {e}")))
        }

        fn delete(&self, account: &str) -> Result<(), KeysError> {
            delete_generic_password(&self.service, account).map_err(|e| match e.code() {
                -25300 => KeysError::NotFound,
                _ => KeysError::Keychain(format!("biometric keychain delete: {e}")),
            })
        }
    }
}

// ---- Windows: Windows Hello biometric prompt before releasing secrets ----
// Secrets live in the Windows Credential Manager (via keyring). Before `get`
// returns a secret, the user must verify via Windows Hello (face/fingerprint/PIN)
// through the UserConsentVerifier WinRT API.
#[cfg(target_os = "windows")]
mod imp {
    use super::BiometricStore;
    use crate::error::KeysError;
    use crate::keyring_store::KeyringStore;
    use crate::SecretStore;

    impl BiometricStore {
        fn delegate(&self) -> KeyringStore {
            KeyringStore::new(&self.service)
        }
    }

    /// Request Windows Hello verification. Returns Ok(()) if the user verified
    /// (face/fingerprint/PIN), or an error if they declined / it's unavailable.
    fn request_consent(message: &str) -> Result<(), KeysError> {
        use windows::core::HSTRING;
        use windows::Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier,
        };
        // Block on the async WinRT call via the thread-pool.
        let operation =
            UserConsentVerifier::RequestVerificationForUploadAsync(&HSTRING::from(message))
                .map_err(|e| KeysError::Keychain(format!("Windows Hello request: {e}")))?;
        // The windows crate's IAsyncOperation can be awaited in a tokio/async
        // context, but SecretStore::get is sync. Use the blocking get() helper.
        let result: UserConsentVerificationResult = operation
            .get()
            .map_err(|e| KeysError::Keychain(format!("Windows Hello verification failed: {e}")))?;
        match result {
            UserConsentVerificationResult::Verified => Ok(()),
            other => Err(KeysError::Keychain(format!(
                "Windows Hello verification denied: {other:?}"
            ))),
        }
    }

    impl SecretStore for BiometricStore {
        fn put(&self, account: &str, secret: &[u8]) -> Result<(), KeysError> {
            self.delegate().put(account, secret)
        }
        fn get(&self, account: &str) -> Result<Vec<u8>, KeysError> {
            // Gate secret release behind a Windows Hello prompt.
            request_consent("config-sync needs Windows Hello to decrypt your synced configs.")?;
            self.delegate().get(account)
        }
        fn delete(&self, account: &str) -> Result<(), KeysError> {
            self.delegate().delete(account)
        }
    }
}

// ---- Linux / FreeBSD fallback: no standard biometric keychain API. ----
// These platforms fall back to the regular keyring store (Secret Service /
// KWallet / GNOME Keyring) without a biometric prompt.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod imp {
    use super::BiometricStore;
    use crate::error::KeysError;
    use crate::keyring_store::KeyringStore;
    use crate::SecretStore;

    impl BiometricStore {
        fn delegate(&self) -> KeyringStore {
            KeyringStore::new(&self.service)
        }
    }

    impl SecretStore for BiometricStore {
        fn put(&self, account: &str, secret: &[u8]) -> Result<(), KeysError> {
            self.delegate().put(account, secret)
        }
        fn get(&self, account: &str) -> Result<Vec<u8>, KeysError> {
            self.delegate().get(account)
        }
        fn delete(&self, account: &str) -> Result<(), KeysError> {
            self.delegate().delete(account)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_biometric_gated_matches_platform() {
        let s = BiometricStore::new("config-sync-test");
        assert_eq!(
            s.is_biometric_gated(),
            cfg!(any(target_os = "macos", target_os = "windows"))
        );
    }

    #[test]
    fn constructs_with_service_name() {
        let s = BiometricStore::new("my-service");
        assert_eq!(s.service, "my-service");
    }

    // NOTE: round-trip tests against the live OS keychain are intentionally NOT
    // run in CI — they would prompt for Touch ID / a password on macOS and
    // touch the host keychain. Run them manually on a dev machine:
    //
    //   cargo test -p cs-keys --features keyring biometric_store::tests::live_ -- --ignored
    //
    #[cfg(all(test, target_os = "macos", feature = "keyring"))]
    #[ignore]
    #[test]
    fn live_macos_biometric_round_trip_prompts() {
        use crate::SecretStore;
        let s = BiometricStore::new("config-sync-biometric-live-test");
        let acct = "biometric-test-account";
        let _ = s.delete(acct); // clean slate
        s.put(acct, b"secret bytes").expect("put");
        // The following get triggers a Touch ID / passcode prompt on macOS:
        let got = s.get(acct).expect("get (approve the prompt)");
        assert_eq!(got, b"secret bytes");
        s.delete(acct).expect("delete");
    }
}
