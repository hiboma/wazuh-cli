//! Credential store abstraction.
//!
//! On macOS, `KeychainStore` backs this trait with the login keychain
//! via the `keyring` crate. On other platforms (and in test builds)
//! we fall through to `UnavailableStore`, which reports every key as
//! unstored. That lets `Config::from_cli_and_env` keep working without
//! special-casing at the call site.
//!
//! `StoreError::Unavailable` vs `StoreError::Backend` is the load-bearing
//! distinction: `Unavailable` means "there is nothing to read from at
//! all" (no default keychain, non-macOS build) and is safe to silently
//! fall through on; `Backend` means "a real access failure" (denied
//! prompt, ACL mismatch) and must NOT fall through — otherwise a stale
//! env var could silently replace a rotated Keychain secret.

use std::fmt;

/// Service name used by the wazuh-cli Keychain backend. All entries
/// this tool manages are scoped under this service.
pub const KEYCHAIN_SERVICE: &str = "dev.wazuh-cli";

/// Logical key for the Wazuh API password stored in the Keychain.
/// The key is used both as the `account` in the Keychain entry and as
/// the identifier surfaced to the user in `credentials status` output.
pub const KEY_API_PASSWORD: &str = "api_password";

#[derive(Debug)]
pub enum StoreError {
    /// The store as a whole is not present on this host. `resolve()`
    /// is free to fall through to the next source (env var, default).
    Unavailable(String),
    /// A real access failure. Surface to the user and do NOT fall
    /// through, to avoid silently using a stale secret.
    Backend(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Unavailable(msg) => write!(f, "credential store unavailable: {}", msg),
            StoreError::Backend(msg) => write!(f, "credential store error: {}", msg),
        }
    }
}

impl std::error::Error for StoreError {}

pub trait CredentialStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}

/// A store that reports every key as missing and rejects writes. Used
/// on non-macOS builds so callers can use a single trait object without
/// platform-specific branching.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub struct UnavailableStore;

impl CredentialStore for UnavailableStore {
    fn get(&self, _key: &str) -> Result<Option<String>, StoreError> {
        Err(StoreError::Unavailable(
            "no credential backend on this platform".to_string(),
        ))
    }
    fn set(&self, _key: &str, _value: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable(
            "no credential backend on this platform".to_string(),
        ))
    }
    fn delete(&self, _key: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable(
            "no credential backend on this platform".to_string(),
        ))
    }
}

/// Return the default store for the current platform.
#[cfg(target_os = "macos")]
pub fn default_store() -> Box<dyn CredentialStore> {
    Box::new(keychain::KeychainStore::new())
}

#[cfg(not(target_os = "macos"))]
pub fn default_store() -> Box<dyn CredentialStore> {
    Box::new(UnavailableStore)
}

#[cfg(target_os = "macos")]
pub(crate) mod keychain {
    use super::{CredentialStore, KEYCHAIN_SERVICE, StoreError};

    pub struct KeychainStore;

    impl KeychainStore {
        pub fn new() -> Self {
            KeychainStore
        }

        fn entry(&self, key: &str) -> Result<keyring::Entry, StoreError> {
            keyring::Entry::new(KEYCHAIN_SERVICE, key).map_err(classify_keyring_err)
        }
    }

    impl CredentialStore for KeychainStore {
        fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
            let entry = self.entry(key)?;
            match entry.get_password() {
                Ok(s) => Ok(Some(s)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }
        fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
            let entry = self.entry(key)?;
            entry.set_password(value).map_err(classify_keyring_err)
        }
        fn delete(&self, key: &str) -> Result<(), StoreError> {
            let entry = self.entry(key)?;
            match entry.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(classify_keyring_err(e)),
            }
        }
    }

    /// `errSecNoDefaultKeychain` from `Security.framework`.
    /// See <https://developer.apple.com/documentation/security/errsecnodefaultkeychain>.
    /// Locale-independent: the OSStatus is the same on every macOS install.
    pub(super) const ERR_SEC_NO_DEFAULT_KEYCHAIN: i32 = -25307;
    pub(super) const ERR_SEC_INVALID_KEYCHAIN: i32 = -25295;

    /// Classify a `keyring::Error` into `Unavailable` (the store as a
    /// whole is not present) vs `Backend` (an actual access failure).
    ///
    /// We prefer to inspect the underlying `security_framework::base::Error`
    /// OSStatus when available: the codes are locale-independent, whereas
    /// the human-readable message text on `keyring::Error` is translated
    /// (e.g. Japanese macOS reports the same condition with different
    /// wording, which would slip past a string-match allowlist and force
    /// the user into the `Backend` branch on a clean machine).
    ///
    /// We keep a string-match heuristic as a fallback for variants that
    /// do not carry a `security_framework::base::Error` source.
    pub(super) fn classify_keyring_err(e: keyring::Error) -> StoreError {
        if let keyring::Error::PlatformFailure(ref boxed) = e
            && let Some(sf_err) = boxed.downcast_ref::<security_framework::base::Error>()
        {
            let code = sf_err.code();
            let msg = e.to_string();
            if code == ERR_SEC_NO_DEFAULT_KEYCHAIN || code == ERR_SEC_INVALID_KEYCHAIN {
                return StoreError::Unavailable(msg);
            }
            return StoreError::Backend(msg);
        }

        // Fallback for non-PlatformFailure errors or unrecognized boxed
        // source types: keep the locale-fragile string match as a last
        // line of defense, but err on the side of Backend (the cautious
        // choice — refuses to fall through).
        let msg = e.to_string();
        let lower = msg.to_lowercase();
        let unavailable = lower.contains("no default keychain")
            || lower.contains("default keychain could not be found")
            || lower.contains("no such keychain");
        if unavailable {
            StoreError::Unavailable(msg)
        } else {
            StoreError::Backend(msg)
        }
    }
}

/// Test-only in-memory store. Useful for exercising `resolve()` paths
/// without touching the real Keychain.
#[cfg(test)]
pub struct MemoryStore {
    inner: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

#[cfg(test)]
impl MemoryStore {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(test)]
impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl CredentialStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.inner.lock().unwrap().get(key).cloned())
    }
    fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.inner
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.inner.lock().unwrap().remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrip() {
        let s = MemoryStore::new();
        assert!(s.get("k").unwrap().is_none());
        s.set("k", "v").unwrap();
        assert_eq!(s.get("k").unwrap().as_deref(), Some("v"));
        s.delete("k").unwrap();
        assert!(s.get("k").unwrap().is_none());
    }

    #[test]
    fn memory_store_delete_missing_is_ok() {
        let s = MemoryStore::new();
        s.delete("missing").unwrap();
    }

    #[test]
    fn unavailable_store_reports_unavailable() {
        let s = UnavailableStore;
        match s.get("k") {
            Err(StoreError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {:?}", other),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_keyring_err_recognizes_no_default_keychain_by_osstatus() {
        // Build a security_framework error directly from the OSStatus,
        // box it through keyring::Error::PlatformFailure, and confirm
        // the classifier maps it to Unavailable regardless of the
        // localized message text.
        let sf = security_framework::base::Error::from_code(
            super::keychain::ERR_SEC_NO_DEFAULT_KEYCHAIN,
        );
        let kr = keyring::Error::PlatformFailure(Box::new(sf));
        match super::keychain::classify_keyring_err(kr) {
            StoreError::Unavailable(_) => {}
            other => panic!("expected Unavailable, got {:?}", other),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_keyring_err_treats_other_osstatus_as_backend() {
        // errSecAuthFailed = -25293 — a real access denial, NOT an
        // "unavailable backend". Must surface as Backend so resolve()
        // refuses to fall through to a stale env var.
        let sf = security_framework::base::Error::from_code(-25293);
        let kr = keyring::Error::PlatformFailure(Box::new(sf));
        match super::keychain::classify_keyring_err(kr) {
            StoreError::Backend(_) => {}
            other => panic!("expected Backend, got {:?}", other),
        }
    }
}
