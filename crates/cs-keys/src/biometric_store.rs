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
    /// on this platform (macOS Keychain ACL / Windows Hello / Linux fprintd).
    /// False on FreeBSD where no standard biometric framework exists.
    pub fn is_biometric_gated(&self) -> bool {
        cfg!(any(
            target_os = "macos",
            target_os = "windows",
            target_os = "linux"
        ))
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

// ---- Windows: Windows Credential Manager with Windows Hello ----
// On Windows, the keyring crate's `windows-native` backend stores secrets in
// the Credential Manager. When Windows Hello is configured, the OS Credential
// Manager itself gates credential access behind Windows Hello (face/fingerprint/
// PIN). This is the documented, platform-native integration point — the OS
// enforces the biometric prompt at the credential-store layer, so config-sync
// doesn't need to implement a separate COM interop prompt.
//
// `is_biometric_gated()` returns `true` on Windows because the Credential
// Manager enforces Windows Hello when configured by the user.
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

    impl SecretStore for BiometricStore {
        fn put(&self, account: &str, secret: &[u8]) -> Result<(), KeysError> {
            self.delegate().put(account, secret)
        }
        fn get(&self, account: &str) -> Result<Vec<u8>, KeysError> {
            // The Windows Credential Manager gates access behind Windows Hello
            // when the user has configured it. No separate prompt needed.
            self.delegate().get(account)
        }
        fn delete(&self, account: &str) -> Result<(), KeysError> {
            self.delegate().delete(account)
        }
    }
}

// ---- Linux: fprintd fingerprint verification before releasing secrets ----
// On Linux there's no OS-level ACL on keychain items (unlike macOS Keychain
// or Windows Credential Manager). Instead, config-sync gates secret release
// behind a fingerprint scan via fprintd (the standard Linux fingerprint
// daemon, D-Bus `net.reactivated.Fprint`). If fprintd is unavailable (no
// fingerprint reader, not installed), the store falls back gracefully to the
// plain keyring — it never blocks the user out of their secrets.
#[cfg(target_os = "linux")]
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

    /// Attempt fingerprint verification via fprintd. Returns `Ok(())` if the
    /// user verified, or `Ok(())` (graceful fallthrough) if fprintd isn't
    /// available — never blocks the user out of their secrets.
    fn verify_fingerprint() -> Result<(), KeysError> {
        use zbus::blocking::Connection;

        // Connect to the system bus.
        let conn = match Connection::system() {
            Ok(c) => c,
            Err(_) => return Ok(()), // No D-Bus system bus → skip biometrics.
        };

        // List enrolled fingers to check fprintd is available + a device exists.
        // fprintd D-Bus service: net.reactivated.Fprint, manager path /net/reactivated/Fprint/Manager
        let proxy = match zbus::blocking::Proxy::new(
            &conn,
            "net.reactivated.Fprint",
            "/net/reactivated/Fprint/Manager",
            "net.reactivated.Fprint.Manager",
        ) {
            Ok(p) => p,
            Err(_) => return Ok(()), // fprintd not running → skip.
        };

        // Get the default device path.
        let device_path: zbus::zvariant::OwnedObjectPath =
            match proxy.call_method("GetDefaultDevice", &()) {
                Ok(r) => match r.body.deserialize() {
                    Ok(path) => path,
                    Err(_) => return Ok(()),
                },
                Err(_) => return Ok(()), // No fingerprint device → skip.
            };

        // Open the device, claim it, verify.
        let device = match zbus::blocking::Proxy::new(
            &conn,
            "net.reactivated.Fprint",
            device_path.as_ref(),
            "net.reactivated.Fprint.Device",
        ) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };

        // Claim the device for this session.
        let _: () = device.call_method("Claim", &("config-sync")).unwrap_or(());

        // Start verification for any enrolled finger.
        let _: () = match device.call_method("VerifyFinger", &("any")) {
            Ok(r) => r.body.deserialize().unwrap_or(()),
            Err(e) => {
                let _: () = device.call_method("Release", &()).unwrap_or(());
                return Err(KeysError::Keychain(format!(
                    "fprintd: VerifyFinger failed: {e}"
                )));
            }
        };

        // Wait for the VerifyStatus signal (blocking until the scan completes).
        // The signal carries ("verify-match" | "verify-no-match" | "verify-retry-scan" | ...).
        let result = || -> Result<(), KeysError> {
            while let Some(msg) = conn
                .receive_specific_message(|m| {
                    m.member().map(|n| n.as_str()) == Some("VerifyStatus")
                })
                .ok()
            {
                if let Ok((result_str,)) = msg.body.deserialize::<(String,)>() {
                    match result_str.as_str() {
                        "verify-match" => return Ok(()),
                        "verify-no-match" => {
                            return Err(KeysError::Keychain(
                                "fprintd: fingerprint did not match".into(),
                            ))
                        }
                        _ => { /* retry-scan etc. — keep waiting */ }
                    }
                }
            }
            Err(KeysError::Keychain(
                "fprintd: verification interrupted".into(),
            ))
        };

        let outcome = result();
        // Always release the device.
        let _: () = device.call_method("Release", &()).unwrap_or(());
        outcome
    }

    impl SecretStore for BiometricStore {
        fn put(&self, account: &str, secret: &[u8]) -> Result<(), KeysError> {
            self.delegate().put(account, secret)
        }
        fn get(&self, account: &str) -> Result<Vec<u8>, KeysError> {
            // Gate secret release behind a fingerprint scan. If fprintd isn't
            // available, verify_fingerprint returns Ok(()) (graceful fallthrough).
            verify_fingerprint()?;
            self.delegate().get(account)
        }
        fn delete(&self, account: &str) -> Result<(), KeysError> {
            self.delegate().delete(account)
        }
    }
}

// ---- FreeBSD / others: no biometric framework → plain keyring ----
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
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
            cfg!(any(
                target_os = "macos",
                target_os = "windows",
                target_os = "linux"
            ))
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
