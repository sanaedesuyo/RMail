use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::account::AccountConfig;
use crate::crypto::{self, EncryptedEnvelope};
use crate::key_store::KeyStore;
use crate::{RMailError, Result};

const MAX_ACCOUNT_FILE_SIZE: u64 = 1024 * 1024;

#[derive(Serialize)]
struct AccountDocumentRef<'a> {
    profile_id: &'a str,
    email: &'a str,
    password: &'a str,
    incoming: &'a crate::account::MailServer,
    outgoing: &'a crate::account::MailServer,
    discovery: crate::account::DiscoveryMethod,
}

impl<'a> From<&'a AccountConfig> for AccountDocumentRef<'a> {
    fn from(account: &'a AccountConfig) -> Self {
        Self {
            profile_id: &account.profile_id,
            email: &account.email,
            password: &account.password,
            incoming: &account.incoming,
            outgoing: &account.outgoing,
            discovery: account.discovery,
        }
    }
}

#[derive(Deserialize)]
struct AccountDocument {
    profile_id: String,
    email: Zeroizing<String>,
    password: Zeroizing<String>,
    incoming: crate::account::MailServer,
    outgoing: crate::account::MailServer,
    discovery: crate::account::DiscoveryMethod,
}

impl AccountDocument {
    fn into_account(mut self) -> Result<AccountConfig> {
        AccountConfig::new(
            std::mem::take(&mut self.profile_id),
            std::mem::take(&mut *self.email),
            std::mem::take(&mut *self.password),
            self.incoming.clone(),
            self.outgoing.clone(),
            self.discovery,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataPaths {
    pub root: PathBuf,
    pub accounts: PathBuf,
    pub mail: PathBuf,
    pub preferences: PathBuf,
}

impl DataPaths {
    pub fn system_default() -> Result<Self> {
        let project =
            ProjectDirs::from("", "", "RMail").ok_or(RMailError::DataDirectoryUnavailable)?;
        Ok(Self::from_root(project.data_local_dir().to_path_buf()))
    }

    pub fn from_root(root: PathBuf) -> Self {
        Self {
            accounts: root.join("accounts"),
            mail: root.join("mail"),
            preferences: root.join("preferences"),
            root,
        }
    }

    pub fn ensure(&self) -> Result<()> {
        for directory in [&self.root, &self.accounts, &self.mail, &self.preferences] {
            fs::create_dir_all(directory).map_err(|source| RMailError::Io {
                action: "创建数据目录",
                path: directory.clone(),
                source,
            })?;
            set_private_directory_permissions(directory)?;
        }
        Ok(())
    }

    fn account_file(&self, profile_id: &str) -> Result<PathBuf> {
        validate_profile_id(profile_id)?;
        Ok(self.accounts.join(format!("{profile_id}.toml")))
    }
}

pub struct AccountRepository<K> {
    paths: DataPaths,
    key_store: K,
}

impl<K: KeyStore> AccountRepository<K> {
    pub fn new(paths: DataPaths, key_store: K) -> Self {
        Self { paths, key_store }
    }

    pub fn paths(&self) -> &DataPaths {
        &self.paths
    }

    pub fn save(&self, account: &AccountConfig) -> Result<()> {
        validate_profile_id(&account.profile_id)?;
        self.paths.ensure()?;
        let destination = self.paths.account_file(&account.profile_id)?;
        if destination.exists() {
            return Err(RMailError::Io {
                action: "保存账号配置",
                path: destination,
                source: std::io::Error::new(std::io::ErrorKind::AlreadyExists, "配置已存在"),
            });
        }

        let plaintext = Zeroizing::new(toml::to_string(&AccountDocumentRef::from(account))?);
        let key = crypto::generate_key();
        let envelope = crypto::seal(&account.profile_id, plaintext.as_bytes(), &key)?;
        let document = toml::to_string_pretty(&envelope)?;

        self.key_store.save_key(&account.profile_id, &key)?;
        if let Err(error) = write_private_atomic(&destination, document.as_bytes()) {
            let _ = self.key_store.delete_key(&account.profile_id);
            return Err(error);
        }
        Ok(())
    }

    pub fn load(&self, profile_id: &str) -> Result<AccountConfig> {
        validate_profile_id(profile_id)?;
        let path = self.paths.account_file(profile_id)?;
        if !path.is_file() {
            return Err(RMailError::ProfileNotFound(profile_id.to_owned()));
        }
        let document = read_limited_utf8(&path, MAX_ACCOUNT_FILE_SIZE)?;
        let envelope: EncryptedEnvelope = toml::from_str(&document)?;
        envelope.validate(profile_id)?;

        let mut key = self.key_store.load_key(profile_id)?;
        let plaintext = crypto::open(&envelope, &key);
        key.zeroize();
        let plaintext = plaintext?;
        let text = std::str::from_utf8(&plaintext)
            .map_err(|_| RMailError::InvalidEnvelope("解密内容不是 UTF-8"))?;
        let account = toml::from_str::<AccountDocument>(text)
            .map_err(|_| RMailError::InvalidEnvelope("解密后的账号配置结构无效"))?
            .into_account()?;
        if account.profile_id != profile_id {
            return Err(RMailError::InvalidEnvelope("解密内容中的配置 ID 不匹配"));
        }
        Ok(account)
    }

    /// 使用原有的系统凭据库密钥原子替换加密账号配置。
    pub fn replace(&self, account: &AccountConfig) -> Result<()> {
        validate_profile_id(&account.profile_id)?;
        let destination = self.paths.account_file(&account.profile_id)?;
        if !destination.is_file() {
            return Err(RMailError::ProfileNotFound(account.profile_id.clone()));
        }
        let mut key = self.key_store.load_key(&account.profile_id)?;
        let plaintext = Zeroizing::new(toml::to_string(&AccountDocumentRef::from(account))?);
        let envelope = crypto::seal(&account.profile_id, plaintext.as_bytes(), &key)?;
        key.zeroize();
        let document = toml::to_string_pretty(&envelope)?;
        write_private_atomic(&destination, document.as_bytes())
    }

    /// 删除加密配置文件，并随后删除对应的系统凭据库密钥。
    ///
    /// 若系统凭据库删除失败，账号文件已不再存在，遗留密钥不包含邮件或凭据数据。
    pub fn delete(&self, profile_id: &str) -> Result<()> {
        validate_profile_id(profile_id)?;
        let path = self.paths.account_file(profile_id)?;
        if !path.is_file() {
            return Err(RMailError::ProfileNotFound(profile_id.to_owned()));
        }
        fs::remove_file(&path).map_err(|source| RMailError::Io {
            action: "删除加密账号配置",
            path,
            source,
        })?;
        self.key_store.delete_key(profile_id)
    }

    pub fn list_profile_ids(&self) -> Result<Vec<String>> {
        self.paths.ensure()?;
        let entries = fs::read_dir(&self.paths.accounts).map_err(|source| RMailError::Io {
            action: "读取账号目录",
            path: self.paths.accounts.clone(),
            source,
        })?;
        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| RMailError::Io {
                action: "读取账号目录项",
                path: self.paths.accounts.clone(),
                source,
            })?;
            let file_type = entry.file_type().map_err(|source| RMailError::Io {
                action: "检查账号配置类型",
                path: entry.path(),
                source,
            })?;
            if !file_type.is_file() || entry.path().extension() != Some(OsStr::new("toml")) {
                continue;
            }
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
                continue;
            };
            if Uuid::parse_str(stem).is_ok() {
                ids.push(stem.to_owned());
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    pub fn resolve_profile(&self, requested: Option<&str>) -> Result<String> {
        if let Some(profile_id) = requested {
            validate_profile_id(profile_id)?;
            return Ok(profile_id.to_owned());
        }
        match self.list_profile_ids()?.as_slice() {
            [] => Err(RMailError::NoProfiles),
            [only] => Ok(only.clone()),
            _ => Err(RMailError::AmbiguousProfile),
        }
    }
}

fn validate_profile_id(profile_id: &str) -> Result<()> {
    let parsed = Uuid::parse_str(profile_id).map_err(|_| RMailError::InvalidProfileId)?;
    if parsed.to_string() != profile_id {
        return Err(RMailError::InvalidProfileId);
    }
    Ok(())
}

fn read_limited_utf8(path: &Path, maximum: u64) -> Result<String> {
    let file = File::open(path).map_err(|source| RMailError::Io {
        action: "打开账号配置",
        path: path.to_path_buf(),
        source,
    })?;
    let mut document = String::new();
    file.take(maximum + 1)
        .read_to_string(&mut document)
        .map_err(|source| RMailError::Io {
            action: "读取账号配置",
            path: path.to_path_buf(),
            source,
        })?;
    if document.len() as u64 > maximum {
        return Err(RMailError::InvalidEnvelope("配置文件超过大小限制"));
    }
    Ok(document)
}

fn write_private_atomic(destination: &Path, contents: &[u8]) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or(RMailError::InvalidEnvelope("配置路径缺少父目录"))?;
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let suffix = u64::from_le_bytes(random);
    let temporary = parent.join(format!(".rmail-{suffix:016x}.tmp"));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary).map_err(|source| RMailError::Io {
            action: "创建临时配置",
            path: temporary.clone(),
            source,
        })?;
        file.write_all(contents).map_err(|source| RMailError::Io {
            action: "写入临时配置",
            path: temporary.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| RMailError::Io {
            action: "同步临时配置",
            path: temporary.clone(),
            source,
        })?;
        fs::rename(&temporary, destination).map_err(|source| RMailError::Io {
            action: "提交账号配置",
            path: destination.to_path_buf(),
            source,
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| RMailError::Io {
        action: "设置数据目录权限",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tempfile::TempDir;

    use super::*;
    use crate::account::{DiscoveryMethod, MailServer, TransportSecurity};
    use crate::crypto::KEY_LENGTH;

    #[derive(Clone, Default)]
    struct MemoryKeyStore(Arc<Mutex<HashMap<String, [u8; KEY_LENGTH]>>>);

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

    fn account(profile_id: &str) -> AccountConfig {
        AccountConfig::new(
            profile_id.to_owned(),
            "alice@example.com".into(),
            "correct horse battery staple".into(),
            MailServer::new("imap.example.com".into(), 993, TransportSecurity::Tls)
                .expect("incoming server"),
            MailServer::new("smtp.example.com".into(), 465, TransportSecurity::Tls)
                .expect("outgoing server"),
            DiscoveryMethod::Guessed,
        )
        .expect("account")
    }

    #[test]
    fn creates_modular_layout_and_round_trips_encrypted_account() {
        let temporary = TempDir::new().expect("temp dir");
        let paths = DataPaths::from_root(temporary.path().join("RMail"));
        let repository = AccountRepository::new(paths.clone(), MemoryKeyStore::default());
        let profile_id = Uuid::new_v4().to_string();
        let original = account(&profile_id);

        repository.save(&original).expect("save account");
        assert!(paths.accounts.is_dir());
        assert!(paths.mail.is_dir());
        assert!(paths.preferences.is_dir());

        let encrypted = fs::read_to_string(paths.account_file(&profile_id).expect("path"))
            .expect("read encrypted envelope");
        assert!(!encrypted.contains("alice@example.com"));
        assert!(!encrypted.contains("correct horse"));
        assert!(!encrypted.contains("imap.example.com"));

        let loaded = repository.load(&profile_id).expect("load account");
        assert_eq!(loaded.email, original.email);
        assert_eq!(loaded.password, original.password);
        assert_eq!(loaded.incoming, original.incoming);
        assert_eq!(repository.list_profile_ids().expect("list"), [profile_id]);
    }

    #[test]
    fn rejects_tampered_ciphertext_and_path_traversal() {
        let temporary = TempDir::new().expect("temp dir");
        let paths = DataPaths::from_root(temporary.path().join("RMail"));
        let repository = AccountRepository::new(paths.clone(), MemoryKeyStore::default());
        let profile_id = Uuid::new_v4().to_string();
        repository
            .save(&account(&profile_id))
            .expect("save account");

        let file = paths.account_file(&profile_id).expect("path");
        let mut document = fs::read_to_string(&file).expect("read envelope");
        document.push_str("\n# tamper does not change authenticated fields\n");
        fs::write(&file, document).expect("write harmless comment");
        assert!(repository.load("../outside").is_err());

        let envelope: EncryptedEnvelope =
            toml::from_str(&fs::read_to_string(&file).expect("read envelope")).expect("parse");
        let mut encoded = toml::to_string(&envelope).expect("serialize");
        encoded = encoded.replace("ciphertext = \"", "ciphertext = \"A");
        fs::write(&file, encoded).expect("tamper ciphertext");
        assert!(repository.load(&profile_id).is_err());

        // Keep the value live so this test also proves the envelope was parseable before tampering.
        assert_eq!(envelope.profile_id(), profile_id);
    }

    #[test]
    fn resolve_requires_id_when_multiple_profiles_exist() {
        let temporary = TempDir::new().expect("temp dir");
        let paths = DataPaths::from_root(temporary.path().join("RMail"));
        let repository = AccountRepository::new(paths, MemoryKeyStore::default());
        for _ in 0..2 {
            let id = Uuid::new_v4().to_string();
            repository.save(&account(&id)).expect("save account");
        }
        assert!(matches!(
            repository.resolve_profile(None),
            Err(RMailError::AmbiguousProfile)
        ));
    }

    #[test]
    fn replaces_and_deletes_account_with_its_key() {
        let temporary = TempDir::new().expect("temp dir");
        let paths = DataPaths::from_root(temporary.path().join("RMail"));
        let store = MemoryKeyStore::default();
        let repository = AccountRepository::new(paths.clone(), store.clone());
        let profile_id = Uuid::new_v4().to_string();
        repository
            .save(&account(&profile_id))
            .expect("save account");

        let updated = AccountConfig::new(
            profile_id.clone(),
            "new-address@example.com".into(),
            "new application password".into(),
            MailServer::new("imap.example.com".into(), 993, TransportSecurity::Tls)
                .expect("incoming"),
            MailServer::new("smtp.example.com".into(), 465, TransportSecurity::Tls)
                .expect("outgoing"),
            DiscoveryMethod::Manual,
        )
        .expect("updated account");
        repository.replace(&updated).expect("replace account");
        assert_eq!(
            repository.load(&profile_id).expect("load").email(),
            "new-address@example.com"
        );

        repository.delete(&profile_id).expect("delete account");
        assert!(!paths.account_file(&profile_id).expect("path").exists());
        assert!(repository.load(&profile_id).is_err());
        assert!(store.load_key(&profile_id).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn account_file_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TempDir::new().expect("temp dir");
        let paths = DataPaths::from_root(temporary.path().join("RMail"));
        let repository = AccountRepository::new(paths.clone(), MemoryKeyStore::default());
        let profile_id = Uuid::new_v4().to_string();
        repository
            .save(&account(&profile_id))
            .expect("save account");
        let mode = fs::metadata(paths.account_file(&profile_id).expect("path"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
