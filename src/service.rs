use uuid::Uuid;

use crate::Result;
use crate::account::{AccountConfig, DiscoveryMethod, MailServer};
use crate::key_store::KeyStore;
use crate::storage::AccountRepository;

/// 可由 CLI 和后续 Tauri 界面共同调用的账号应用服务。
pub struct AccountService<'a, K> {
    repository: &'a AccountRepository<K>,
}

impl<'a, K: KeyStore> AccountService<'a, K> {
    pub fn new(repository: &'a AccountRepository<K>) -> Self {
        Self { repository }
    }

    pub fn create(
        &self,
        email: String,
        password: String,
        incoming: MailServer,
        outgoing: MailServer,
        discovery: DiscoveryMethod,
    ) -> Result<String> {
        let profile_id = Uuid::new_v4().to_string();
        let account = AccountConfig::new(
            profile_id.clone(),
            email,
            password,
            incoming,
            outgoing,
            discovery,
        )?;
        self.repository.save(&account)?;
        Ok(profile_id)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use tempfile::TempDir;

    use super::*;
    use crate::RMailError;
    use crate::crypto::KEY_LENGTH;
    use crate::server::discover;
    use crate::storage::DataPaths;

    #[derive(Default)]
    struct MemoryKeyStore(Mutex<HashMap<String, [u8; KEY_LENGTH]>>);

    impl KeyStore for MemoryKeyStore {
        fn save_key(&self, profile_id: &str, key: &[u8; KEY_LENGTH]) -> Result<()> {
            self.0
                .lock()
                .expect("memory key store lock")
                .insert(profile_id.to_owned(), *key);
            Ok(())
        }

        fn load_key(&self, profile_id: &str) -> Result<[u8; KEY_LENGTH]> {
            self.0
                .lock()
                .expect("memory key store lock")
                .get(profile_id)
                .copied()
                .ok_or_else(|| RMailError::KeyStore("missing test key".into()))
        }

        fn delete_key(&self, profile_id: &str) -> Result<()> {
            self.0
                .lock()
                .expect("memory key store lock")
                .remove(profile_id);
            Ok(())
        }
    }

    #[test]
    fn creates_and_persists_account_through_application_service() {
        let temporary = TempDir::new().expect("temp dir");
        let repository = AccountRepository::new(
            DataPaths::from_root(temporary.path().join("RMail")),
            MemoryKeyStore::default(),
        );
        let servers = discover("alice@example.com").expect("server guess");
        let profile_id = AccountService::new(&repository)
            .create(
                "alice@example.com".into(),
                "test application password".into(),
                servers.incoming,
                servers.outgoing,
                servers.method,
            )
            .expect("create account");

        let loaded = repository.load(&profile_id).expect("load account");
        assert_eq!(loaded.profile_id(), profile_id);
        assert_eq!(loaded.email(), "alice@example.com");
    }
}
