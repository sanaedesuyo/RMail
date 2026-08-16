use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, EncryptedEnvelope};
use crate::key_store::KeyStore;
use crate::storage::DataPaths;
use crate::{RMailError, Result};

pub const DEFAULT_MAX_ENTRIES: usize = 1_000;
const MAX_ENTRIES: usize = 100_000;
const MAX_LOG_FILE_BYTES: u64 = 4 * 1024 * 1024;
const PREFERENCES_ID: &str = "logging-preferences-v1";
const PREFERENCES_FILE: &str = "logging.toml";
const LOG_FILE: &str = "rmail.log";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct LoggingPreferences {
    max_entries: usize,
}

pub struct Logger<K> {
    paths: DataPaths,
    key_store: K,
}

impl<K: KeyStore> Logger<K> {
    pub fn new(paths: DataPaths, key_store: K) -> Self {
        Self { paths, key_store }
    }

    pub fn log_path(&self) -> PathBuf {
        self.paths.logs.join(LOG_FILE)
    }

    pub fn max_entries(&self) -> Result<usize> {
        let path = self.preferences_path();
        if !path.is_file() {
            return Ok(DEFAULT_MAX_ENTRIES);
        }
        let document = read_limited_utf8(&path, MAX_LOG_FILE_BYTES, "读取日志偏好")?;
        let envelope: EncryptedEnvelope = toml::from_str(&document)?;
        envelope.validate(PREFERENCES_ID)?;
        let mut key = self.key_store.load_key(PREFERENCES_ID)?;
        let plaintext = crypto::open(&envelope, &key);
        key.zeroize();
        let plaintext = plaintext?;
        let preferences: LoggingPreferences = toml::from_str(
            std::str::from_utf8(&plaintext)
                .map_err(|_| RMailError::InvalidEnvelope("日志偏好不是 UTF-8"))?,
        )
        .map_err(|_| RMailError::InvalidEnvelope("日志偏好格式无效"))?;
        validate_max_entries(preferences.max_entries)?;
        Ok(preferences.max_entries)
    }

    pub fn set_max_entries(&self, max_entries: usize) -> Result<()> {
        validate_max_entries(max_entries)?;
        self.paths.ensure()?;
        let preferences = Zeroizing::new(toml::to_string(&LoggingPreferences { max_entries })?);
        let path = self.preferences_path();
        let mut key = if path.is_file() {
            Zeroizing::new(self.key_store.load_key(PREFERENCES_ID)?)
        } else {
            let key = crypto::generate_key();
            self.key_store.save_key(PREFERENCES_ID, &key)?;
            key
        };
        let envelope = crypto::seal(PREFERENCES_ID, preferences.as_bytes(), &key)?;
        key.zeroize();
        let document = toml::to_string_pretty(&envelope)?;
        if let Err(error) = write_private_atomic(&path, document.as_bytes()) {
            if !path.exists() {
                let _ = self.key_store.delete_key(PREFERENCES_ID);
            }
            return Err(error);
        }
        self.trim_to(max_entries)
    }

    /// 记录一个固定、非敏感的事件代码。禁止将用户数据拼入事件代码。
    pub fn record(&self, level: LogLevel, event_code: &'static str) -> Result<()> {
        validate_event_code(event_code)?;
        self.paths.ensure()?;
        let max_entries = self.max_entries()?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RMailError::InvalidEnvelope("系统时间早于 Unix epoch"))?
            .as_millis();
        let entry = format!("{timestamp}\t{level}\t{event_code}\n");
        let mut entries = self.read_entries()?;
        entries.push(entry);
        retain_latest(&mut entries, max_entries);
        write_private_atomic(&self.log_path(), entries.concat().as_bytes())
    }

    fn trim_to(&self, max_entries: usize) -> Result<()> {
        let path = self.log_path();
        if !path.is_file() {
            return Ok(());
        }
        let mut entries = self.read_entries()?;
        retain_latest(&mut entries, max_entries);
        write_private_atomic(&path, entries.concat().as_bytes())
    }

    fn preferences_path(&self) -> PathBuf {
        self.paths.preferences.join(PREFERENCES_FILE)
    }

    fn read_entries(&self) -> Result<Vec<String>> {
        let path = self.log_path();
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let text = read_limited_utf8(&path, MAX_LOG_FILE_BYTES, "读取日志文件")?;
        Ok(text
            .lines()
            .filter(|line| is_valid_entry(line))
            .map(|line| format!("{line}\n"))
            .collect())
    }
}

fn validate_max_entries(max_entries: usize) -> Result<()> {
    if !(1..=MAX_ENTRIES).contains(&max_entries) {
        return Err(RMailError::InvalidChoice(
            "日志条目上限必须在 1 到 100000 之间",
        ));
    }
    Ok(())
}

fn validate_event_code(event_code: &str) -> Result<()> {
    if event_code.is_empty()
        || event_code.len() > 64
        || !event_code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(RMailError::InvalidChoice("日志事件代码无效"));
    }
    Ok(())
}

fn is_valid_entry(line: &str) -> bool {
    let mut fields = line.split('\t');
    fields
        .next()
        .is_some_and(|timestamp| timestamp.parse::<u128>().is_ok())
        && fields
            .next()
            .is_some_and(|level| matches!(level, "INFO" | "WARN" | "ERROR"))
        && fields
            .next()
            .is_some_and(|code| validate_event_code(code).is_ok())
        && fields.next().is_none()
}

fn retain_latest(entries: &mut Vec<String>, max_entries: usize) {
    let excess = entries.len().saturating_sub(max_entries);
    if excess > 0 {
        entries.drain(..excess);
    }
}

fn read_limited_utf8(path: &Path, maximum: u64, action: &'static str) -> Result<String> {
    let file = fs::File::open(path).map_err(|source| RMailError::Io {
        action,
        path: path.to_path_buf(),
        source,
    })?;
    let mut text = String::new();
    file.take(maximum + 1)
        .read_to_string(&mut text)
        .map_err(|source| RMailError::Io {
            action,
            path: path.to_path_buf(),
            source,
        })?;
    if text.len() as u64 > maximum {
        return Err(RMailError::InvalidEnvelope("日志文件超过大小限制"));
    }
    Ok(text)
}

fn write_private_atomic(destination: &Path, contents: &[u8]) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or(RMailError::InvalidEnvelope("日志路径缺少父目录"))?;
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(
        ".rmail-log-{:016x}.tmp",
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
        let mut file = options.open(&temporary).map_err(|source| RMailError::Io {
            action: "创建临时日志文件",
            path: temporary.clone(),
            source,
        })?;
        file.write_all(contents)
            .and_then(|_| file.sync_all())
            .map_err(|source| RMailError::Io {
                action: "写入日志文件",
                path: temporary.clone(),
                source,
            })?;
        fs::rename(&temporary, destination).map_err(|source| RMailError::Io {
            action: "提交日志文件",
            path: destination.to_path_buf(),
            source,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KEY_LENGTH;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

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
    fn encrypts_preferences_and_retains_latest_entries() {
        let temporary = TempDir::new().expect("temp dir");
        let paths = DataPaths::from_root(temporary.path().join("RMail"));
        let logger = Logger::new(paths.clone(), MemoryKeyStore::default());
        logger.set_max_entries(2).expect("set limit");
        logger.record(LogLevel::Info, "test.first").expect("first");
        logger
            .record(LogLevel::Warn, "test.second")
            .expect("second");
        logger.record(LogLevel::Error, "test.third").expect("third");
        let log = fs::read_to_string(logger.log_path()).expect("read log");
        assert!(!log.contains("test.first"));
        assert!(log.contains("test.second"));
        assert!(log.contains("test.third"));
        let preferences =
            fs::read_to_string(paths.preferences.join(PREFERENCES_FILE)).expect("read preferences");
        assert!(!preferences.contains("max_entries"));
        assert_eq!(logger.max_entries().expect("read limit"), 2);
    }

    #[test]
    fn rejects_sensitive_or_invalid_event_codes_and_limits() {
        assert!(validate_event_code("email=alice@example.com").is_err());
        assert!(validate_max_entries(0).is_err());
        assert!(validate_max_entries(MAX_ENTRIES + 1).is_err());
    }
}
