use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, EncryptedEnvelope};
use crate::key_store::KeyStore;
use crate::mail::{MessageSource, ReceivedMessage};
use crate::storage::DataPaths;
use crate::{RMailError, Result};

const INDEX_FILE: &str = "index.toml";
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailSummary {
    pub account_id: String,
    pub message_id: String,
    pub mailbox: String,
    pub unread: bool,
    pub starred: bool,
    pub trashed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalMailbox {
    New,
    Sent,
    Trash,
    Starred,
}

#[derive(Debug, Deserialize, Serialize)]
struct MailIndex {
    account_id: String,
    mailboxes: Vec<String>,
    messages: Vec<StoredMessage>,
}
#[derive(Debug, Deserialize, Serialize)]
struct StoredMessage {
    id: String,
    mailbox: String,
    source_id: Option<String>,
    unread: bool,
    starred: bool,
    sent: bool,
    trashed_at: Option<u64>,
    original_mailbox: Option<String>,
    raw: Zeroizing<Vec<u8>>,
}

pub struct MailStore<K> {
    paths: DataPaths,
    key_store: K,
}

impl<K: KeyStore> MailStore<K> {
    pub fn new(paths: DataPaths, key_store: K) -> Self {
        Self { paths, key_store }
    }

    pub fn sync_mailboxes(
        &self,
        account_id: &str,
        mailboxes: impl IntoIterator<Item = String>,
    ) -> Result<()> {
        self.modify(account_id, |index| {
            for mailbox in mailboxes {
                if valid_mailbox(&mailbox) && !index.mailboxes.contains(&mailbox) {
                    index.mailboxes.push(mailbox);
                }
            }
            if !index.mailboxes.iter().any(|box_name| box_name == "INBOX") {
                index.mailboxes.push("INBOX".into());
            }
            Ok(())
        })
    }

    pub fn save_received(
        &self,
        account_id: &str,
        mailbox: &str,
        messages: Vec<ReceivedMessage>,
    ) -> Result<()> {
        if !valid_mailbox(mailbox) {
            return Err(RMailError::InvalidMessage("邮件箱名称无效"));
        }
        self.modify(account_id, |index| {
            if !index.mailboxes.contains(&mailbox.to_owned()) {
                index.mailboxes.push(mailbox.to_owned());
            }
            for message in messages {
                let source_id = source_id(&message.source, mailbox);
                let unread = !message
                    .flags
                    .iter()
                    .any(|flag| flag.eq_ignore_ascii_case("\\Seen"));
                let starred = message
                    .flags
                    .iter()
                    .any(|flag| flag.eq_ignore_ascii_case("\\Flagged"));
                if let Some(existing) = index
                    .messages
                    .iter_mut()
                    .find(|stored| stored.source_id.as_deref() == Some(&source_id))
                {
                    existing.unread = unread;
                    existing.starred = starred;
                    existing.raw = message.raw;
                } else {
                    index.messages.push(StoredMessage {
                        id: Uuid::new_v4().to_string(),
                        mailbox: mailbox.into(),
                        source_id: Some(source_id),
                        unread,
                        starred,
                        sent: false,
                        trashed_at: None,
                        original_mailbox: None,
                        raw: message.raw,
                    });
                }
            }
            Ok(())
        })
    }

    pub fn save_sent(&self, account_id: &str, raw: Vec<u8>) -> Result<()> {
        self.modify(account_id, |index| {
            if !index.mailboxes.contains(&"Sent".to_owned()) {
                index.mailboxes.push("Sent".into());
            }
            index.messages.push(StoredMessage {
                id: Uuid::new_v4().to_string(),
                mailbox: "Sent".into(),
                source_id: None,
                unread: false,
                starred: false,
                sent: true,
                trashed_at: None,
                original_mailbox: None,
                raw: Zeroizing::new(raw),
            });
            Ok(())
        })
    }

    pub fn delete(&self, account_id: &str, message_id: &str) -> Result<()> {
        self.modify(account_id, |index| {
            let message = find_live(index, message_id)?;
            message.original_mailbox = Some(message.mailbox.clone());
            message.mailbox = "Trash".into();
            message.trashed_at = Some(now_seconds()?);
            Ok(())
        })
    }
    pub fn restore(&self, account_id: &str, message_id: &str) -> Result<()> {
        self.modify(account_id, |index| {
            let message = index
                .messages
                .iter_mut()
                .find(|message| message.id == message_id && message.trashed_at.is_some())
                .ok_or(RMailError::InvalidMessage("回收站中不存在该邮件"))?;
            message.mailbox = message
                .original_mailbox
                .take()
                .unwrap_or_else(|| "INBOX".into());
            message.trashed_at = None;
            Ok(())
        })
    }
    pub fn purge(&self, account_id: &str, message_id: &str) -> Result<()> {
        self.modify(account_id, |index| {
            let position = index
                .messages
                .iter()
                .position(|message| message.id == message_id && message.trashed_at.is_some())
                .ok_or(RMailError::InvalidMessage("回收站中不存在该邮件"))?;
            index.messages.remove(position);
            Ok(())
        })
    }
    pub fn list_account(
        &self,
        account_id: &str,
        mailbox: Option<&str>,
    ) -> Result<Vec<MailSummary>> {
        let mut index = self.load(account_id)?;
        cleanup(&mut index)?;
        self.save(account_id, &index)?;
        Ok(index
            .messages
            .iter()
            .filter(|message| mailbox.is_none_or(|name| message.mailbox == name))
            .map(|message| summary(account_id, message))
            .collect())
    }
    pub fn list_local(
        &self,
        accounts: &[String],
        mailbox: LocalMailbox,
    ) -> Result<Vec<MailSummary>> {
        let mut result = Vec::new();
        for account_id in accounts {
            let messages = self.list_account(account_id, None)?;
            result.extend(messages.into_iter().filter(|message| match mailbox {
                LocalMailbox::New => message.unread && !message.trashed,
                LocalMailbox::Sent => message.mailbox == "Sent" && !message.trashed,
                LocalMailbox::Trash => message.trashed,
                LocalMailbox::Starred => message.starred && !message.trashed,
            }));
        }
        Ok(result)
    }

    fn modify(
        &self,
        account_id: &str,
        operation: impl FnOnce(&mut MailIndex) -> Result<()>,
    ) -> Result<()> {
        let mut index = self.load(account_id)?;
        cleanup(&mut index)?;
        operation(&mut index)?;
        self.save(account_id, &index)
    }
    fn load(&self, account_id: &str) -> Result<MailIndex> {
        validate_account_id(account_id)?;
        let path = self.index_path(account_id);
        if !path.is_file() {
            return Ok(MailIndex {
                account_id: account_id.into(),
                mailboxes: vec!["INBOX".into()],
                messages: Vec::new(),
            });
        }
        let document = read_limited(&path)?;
        let envelope: EncryptedEnvelope = toml::from_str(&document)?;
        envelope.validate(account_id)?;
        let mut key = Zeroizing::new(self.key_store.load_key(account_id)?);
        let plain = crypto::open(&envelope, &key);
        key.zeroize();
        let plain = plain?;
        let index: MailIndex = toml::from_str(
            std::str::from_utf8(&plain)
                .map_err(|_| RMailError::InvalidEnvelope("邮件索引不是 UTF-8"))?,
        )
        .map_err(|_| RMailError::InvalidEnvelope("邮件索引格式无效"))?;
        if index.account_id != account_id {
            return Err(RMailError::InvalidEnvelope("邮件索引账号不匹配"));
        }
        Ok(index)
    }
    fn save(&self, account_id: &str, index: &MailIndex) -> Result<()> {
        validate_account_id(account_id)?;
        self.paths.ensure()?;
        let directory = self.paths.mail.join(account_id);
        fs::create_dir_all(&directory).map_err(|source| RMailError::Io {
            action: "创建邮件目录",
            path: directory.clone(),
            source,
        })?;
        set_private(&directory)?;
        let path = self.index_path(account_id);
        let mut new_key = false;
        let mut key = if path.is_file() {
            Zeroizing::new(self.key_store.load_key(account_id)?)
        } else {
            new_key = true;
            let key = crypto::generate_key();
            self.key_store.save_key(account_id, &key)?;
            key
        };
        let plaintext = Zeroizing::new(toml::to_string(index)?);
        let envelope = crypto::seal(account_id, plaintext.as_bytes(), &key)?;
        key.zeroize();
        let document = toml::to_string_pretty(&envelope)?;
        if let Err(error) = write_private(&path, document.as_bytes()) {
            if new_key {
                let _ = self.key_store.delete_key(account_id);
            }
            return Err(error);
        }
        Ok(())
    }
    fn index_path(&self, account_id: &str) -> PathBuf {
        self.paths.mail.join(account_id).join(INDEX_FILE)
    }
}

fn source_id(source: &MessageSource, mailbox: &str) -> String {
    match source {
        MessageSource::Imap { uid, sequence } => {
            format!("imap:{mailbox}:{}", uid.unwrap_or(*sequence))
        }
        MessageSource::Pop3 { number, uidl } => {
            format!("pop3:{}", uidl.as_deref().unwrap_or(&number.to_string()))
        }
    }
}
fn summary(account_id: &str, message: &StoredMessage) -> MailSummary {
    MailSummary {
        account_id: account_id.into(),
        message_id: message.id.clone(),
        mailbox: message.mailbox.clone(),
        unread: message.unread,
        starred: message.starred,
        trashed: message.trashed_at.is_some(),
    }
}
fn find_live<'a>(index: &'a mut MailIndex, id: &str) -> Result<&'a mut StoredMessage> {
    index
        .messages
        .iter_mut()
        .find(|message| message.id == id && message.trashed_at.is_none())
        .ok_or(RMailError::InvalidMessage("找不到可删除的邮件"))
}
fn cleanup(index: &mut MailIndex) -> Result<()> {
    let cutoff = now_seconds()?.saturating_sub(RETENTION_SECONDS);
    index
        .messages
        .retain(|message| message.trashed_at.is_none_or(|time| time > cutoff));
    Ok(())
}
fn now_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RMailError::InvalidEnvelope("系统时间早于 Unix epoch"))?
        .as_secs())
}
fn valid_mailbox(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && !value.contains(['\r', '\n', '\0'])
}
fn validate_account_id(value: &str) -> Result<()> {
    Uuid::parse_str(value)
        .map_err(|_| RMailError::InvalidProfileId)
        .map(|_| ())
}
fn read_limited(path: &Path) -> Result<String> {
    let file = fs::File::open(path).map_err(|source| RMailError::Io {
        action: "读取邮件索引",
        path: path.into(),
        source,
    })?;
    let mut text = String::new();
    file.take(MAX_INDEX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|source| RMailError::Io {
            action: "读取邮件索引",
            path: path.into(),
            source,
        })?;
    if text.len() as u64 > MAX_INDEX_BYTES {
        return Err(RMailError::InvalidEnvelope("邮件索引超过大小限制"));
    }
    Ok(text)
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(RMailError::InvalidEnvelope("邮件路径无父目录"))?;
    let mut random = [0; 8];
    OsRng.fill_bytes(&mut random);
    let temp = parent.join(format!(
        ".rmail-mail-{:016x}.tmp",
        u64::from_le_bytes(random)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp).map_err(|source| RMailError::Io {
            action: "创建临时邮件索引",
            path: temp.clone(),
            source,
        })?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|source| RMailError::Io {
                action: "写入邮件索引",
                path: temp.clone(),
                source,
            })?;
        fs::rename(&temp, path).map_err(|source| RMailError::Io {
            action: "提交邮件索引",
            path: path.into(),
            source,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
#[cfg(unix)]
fn set_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| RMailError::Io {
        action: "设置邮件目录权限",
        path: path.into(),
        source,
    })
}
#[cfg(not(unix))]
fn set_private(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tempfile::TempDir;

    use super::*;
    use crate::crypto::KEY_LENGTH;

    #[derive(Clone, Default)]
    struct MemoryKeyStore(Arc<Mutex<HashMap<String, [u8; KEY_LENGTH]>>>);

    impl KeyStore for MemoryKeyStore {
        fn save_key(&self, id: &str, key: &[u8; KEY_LENGTH]) -> Result<()> {
            self.0.lock().expect("lock").insert(id.into(), *key);
            Ok(())
        }
        fn load_key(&self, id: &str) -> Result<[u8; KEY_LENGTH]> {
            self.0
                .lock()
                .expect("lock")
                .get(id)
                .copied()
                .ok_or_else(|| RMailError::KeyStore("missing test key".into()))
        }
        fn delete_key(&self, id: &str) -> Result<()> {
            self.0.lock().expect("lock").remove(id);
            Ok(())
        }
    }

    #[test]
    fn encrypts_messages_and_supports_trash_restore_and_purge() {
        let temporary = TempDir::new().expect("temp dir");
        let paths = DataPaths::from_root(temporary.path().join("RMail"));
        let store = MailStore::new(paths.clone(), MemoryKeyStore::default());
        let account = Uuid::new_v4().to_string();
        store
            .save_sent(&account, b"Subject: private\r\n\r\nprivate body".to_vec())
            .expect("save sent");
        let sent = store
            .list_local(std::slice::from_ref(&account), LocalMailbox::Sent)
            .expect("list sent");
        assert_eq!(sent.len(), 1);
        let id = sent[0].message_id.clone();
        let encrypted =
            fs::read_to_string(paths.mail.join(&account).join(INDEX_FILE)).expect("read index");
        assert!(!encrypted.contains("private body"));

        store.delete(&account, &id).expect("delete");
        assert_eq!(
            store
                .list_local(std::slice::from_ref(&account), LocalMailbox::Trash)
                .expect("trash")
                .len(),
            1
        );
        store.restore(&account, &id).expect("restore");
        assert_eq!(
            store
                .list_local(std::slice::from_ref(&account), LocalMailbox::Sent)
                .expect("sent")
                .len(),
            1
        );
        store.delete(&account, &id).expect("delete again");
        store.purge(&account, &id).expect("purge");
        assert!(store.list_account(&account, None).expect("list").is_empty());
    }
}
