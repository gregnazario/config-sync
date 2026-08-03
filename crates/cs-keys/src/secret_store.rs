//! Abstract secret storage. Production uses [`KeyringStore`] (behind the
//! `keyring` feature); tests and CI use [`InMemoryStore`].

use crate::error::KeysError;
use std::collections::HashMap;
use std::sync::Mutex;

pub trait SecretStore: Send + Sync {
    fn put(&self, account: &str, secret: &[u8]) -> Result<(), KeysError>;
    fn get(&self, account: &str) -> Result<Vec<u8>, KeysError>;
    fn delete(&self, account: &str) -> Result<(), KeysError>;
}

#[derive(Default)]
pub struct InMemoryStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemoryStore {
    fn put(&self, account: &str, secret: &[u8]) -> Result<(), KeysError> {
        self.map
            .lock()
            .unwrap()
            .insert(account.to_string(), secret.to_vec());
        Ok(())
    }

    fn get(&self, account: &str) -> Result<Vec<u8>, KeysError> {
        self.map
            .lock()
            .unwrap()
            .get(account)
            .cloned()
            .ok_or(KeysError::NotFound)
    }

    fn delete(&self, account: &str) -> Result<(), KeysError> {
        self.map
            .lock()
            .unwrap()
            .remove(account)
            .ok_or(KeysError::NotFound)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_delete_round_trip() {
        let s = InMemoryStore::new();
        s.put("rik", &[1, 2, 3]).unwrap();
        assert_eq!(s.get("rik").unwrap(), vec![1, 2, 3]);
        s.delete("rik").unwrap();
        assert!(s.get("rik").is_err());
    }

    #[test]
    fn missing_key_is_not_found() {
        let s = InMemoryStore::new();
        assert!(matches!(s.get("x").err().unwrap(), KeysError::NotFound));
    }

    #[test]
    fn delete_missing_is_not_found() {
        let s = InMemoryStore::new();
        assert!(matches!(s.delete("x").err().unwrap(), KeysError::NotFound));
    }

    #[test]
    fn overwrite_replaces_value() {
        let s = InMemoryStore::new();
        s.put("k", b"v1").unwrap();
        s.put("k", b"v2").unwrap();
        assert_eq!(s.get("k").unwrap(), b"v2".to_vec());
    }
}
