use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{RMailError, Result};

pub const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 24;
const ENVELOPE_VERSION: u8 = 1;
const CIPHER_NAME: &str = "xchacha20poly1305";

#[derive(Debug, Deserialize, Serialize)]
pub struct EncryptedEnvelope {
    version: u8,
    profile_id: String,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

impl EncryptedEnvelope {
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn validate(&self, expected_profile_id: &str) -> Result<()> {
        if self.version != ENVELOPE_VERSION {
            return Err(RMailError::InvalidEnvelope("不支持的格式版本"));
        }
        if self.cipher != CIPHER_NAME {
            return Err(RMailError::InvalidEnvelope("不支持的加密算法"));
        }
        if self.profile_id != expected_profile_id {
            return Err(RMailError::InvalidEnvelope("配置 ID 与文件名不一致"));
        }
        Ok(())
    }
}

pub fn generate_key() -> Zeroizing<[u8; KEY_LENGTH]> {
    let mut key = Zeroizing::new([0_u8; KEY_LENGTH]);
    OsRng.fill_bytes(key.as_mut());
    key
}

pub fn seal(
    profile_id: &str,
    plaintext: &[u8],
    key: &[u8; KEY_LENGTH],
) -> Result<EncryptedEnvelope> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0_u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let aad = additional_data(profile_id);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| RMailError::InvalidEnvelope("加密失败"))?;

    Ok(EncryptedEnvelope {
        version: ENVELOPE_VERSION,
        profile_id: profile_id.to_owned(),
        cipher: CIPHER_NAME.to_owned(),
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(ciphertext),
    })
}

pub fn open(envelope: &EncryptedEnvelope, key: &[u8; KEY_LENGTH]) -> Result<Zeroizing<Vec<u8>>> {
    envelope.validate(envelope.profile_id())?;
    let nonce = BASE64
        .decode(&envelope.nonce)
        .map_err(|_| RMailError::InvalidEnvelope("nonce 不是有效的 Base64"))?;
    if nonce.len() != NONCE_LENGTH {
        return Err(RMailError::InvalidEnvelope("nonce 长度无效"));
    }
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|_| RMailError::InvalidEnvelope("密文不是有效的 Base64"))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let aad = additional_data(envelope.profile_id());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| RMailError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

fn additional_data(profile_id: &str) -> String {
    format!("RMail/account-config/v{ENVELOPE_VERSION}/{profile_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_round_trip_uses_random_nonces() {
        let key = [7_u8; KEY_LENGTH];
        let first = seal("profile", b"secret", &key).expect("encrypt first");
        let second = seal("profile", b"secret", &key).expect("encrypt second");
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(&*open(&first, &key).expect("decrypt"), b"secret");
    }

    #[test]
    fn tampering_and_wrong_keys_are_rejected() {
        let key = [7_u8; KEY_LENGTH];
        let wrong_key = [8_u8; KEY_LENGTH];
        let mut envelope = seal("profile", b"secret", &key).expect("encrypt");
        assert!(open(&envelope, &wrong_key).is_err());

        envelope.ciphertext.push('A');
        assert!(open(&envelope, &key).is_err());
    }
}
