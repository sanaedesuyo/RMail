use zeroize::Zeroize;

use crate::crypto::KEY_LENGTH;
use crate::{RMailError, Result};

const SERVICE_NAME: &str = "RMail.account-key";

pub trait KeyStore {
    fn save_key(&self, profile_id: &str, key: &[u8; KEY_LENGTH]) -> Result<()>;
    fn load_key(&self, profile_id: &str) -> Result<[u8; KEY_LENGTH]>;
    fn delete_key(&self, profile_id: &str) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OsKeyStore;

impl OsKeyStore {
    fn entry(profile_id: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE_NAME, profile_id)
            .map_err(|error| RMailError::KeyStore(error.to_string()))
    }
}

impl KeyStore for OsKeyStore {
    fn save_key(&self, profile_id: &str, key: &[u8; KEY_LENGTH]) -> Result<()> {
        Self::entry(profile_id)?
            .set_secret(key)
            .map_err(|error| RMailError::KeyStore(error.to_string()))
    }

    fn load_key(&self, profile_id: &str) -> Result<[u8; KEY_LENGTH]> {
        let mut secret = Self::entry(profile_id)?
            .get_secret()
            .map_err(|error| RMailError::KeyStore(error.to_string()))?;
        if secret.len() != KEY_LENGTH {
            secret.zeroize();
            return Err(RMailError::KeyStore("保存的密钥长度无效".to_owned()));
        }
        let mut key = [0_u8; KEY_LENGTH];
        key.copy_from_slice(&secret);
        secret.zeroize();
        Ok(key)
    }

    fn delete_key(&self, profile_id: &str) -> Result<()> {
        Self::entry(profile_id)?
            .delete_credential()
            .map_err(|error| RMailError::KeyStore(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[test]
    #[ignore = "uses the real operating-system credential store"]
    fn os_key_store_round_trip() {
        let profile_id = Uuid::new_v4().to_string();
        let expected = [42_u8; KEY_LENGTH];
        let store = OsKeyStore;

        store
            .save_key(&profile_id, &expected)
            .expect("save test key");
        let loaded = store.load_key(&profile_id);
        let cleanup = store.delete_key(&profile_id);

        assert_eq!(loaded.expect("load test key"), expected);
        cleanup.expect("delete test key");
    }
}
