use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{RMailError, Result};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportSecurity {
    Tls,
    StartTls,
}

impl fmt::Display for TransportSecurity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls => formatter.write_str("TLS"),
            Self::StartTls => formatter.write_str("STARTTLS"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MailServer {
    pub host: String,
    pub port: u16,
    pub security: TransportSecurity,
}

impl MailServer {
    pub fn new(host: String, port: u16, security: TransportSecurity) -> Result<Self> {
        validate_host(&host)?;
        if port == 0 {
            return Err(RMailError::InvalidServer("端口不能为 0"));
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
            security,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    Preset,
    Guessed,
    Manual,
}

impl fmt::Display for DiscoveryMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preset => formatter.write_str("内置服务商预设"),
            Self::Guessed => formatter.write_str("域名规则推断"),
            Self::Manual => formatter.write_str("用户手动配置"),
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct AccountConfig {
    pub(crate) profile_id: String,
    pub(crate) email: zeroize::Zeroizing<String>,
    pub(crate) password: zeroize::Zeroizing<String>,
    pub(crate) incoming: MailServer,
    pub(crate) outgoing: MailServer,
    pub(crate) discovery: DiscoveryMethod,
}

impl AccountConfig {
    pub fn new(
        profile_id: String,
        email: String,
        password: String,
        incoming: MailServer,
        outgoing: MailServer,
        discovery: DiscoveryMethod,
    ) -> Result<Self> {
        let email = zeroize::Zeroizing::new(email);
        let password = zeroize::Zeroizing::new(password);
        crate::server::email_domain(&email)?;
        if password.is_empty() {
            return Err(RMailError::EmptyPassword);
        }
        Ok(Self {
            profile_id,
            email,
            password,
            incoming,
            outgoing,
            discovery,
        })
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn incoming(&self) -> &MailServer {
        &self.incoming
    }

    pub fn outgoing(&self) -> &MailServer {
        &self.outgoing
    }

    pub fn discovery(&self) -> DiscoveryMethod {
        self.discovery
    }
}

impl fmt::Debug for AccountConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountConfig")
            .field("profile_id", &self.profile_id)
            .field("email", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("incoming", &self.incoming)
            .field("outgoing", &self.outgoing)
            .field("discovery", &self.discovery)
            .finish()
    }
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() || host.len() > 253 {
        return Err(RMailError::InvalidServer("服务器域名长度无效"));
    }
    if !host.is_ascii() || host.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(RMailError::InvalidServer(
            "服务器域名必须是 ASCII 且不能包含空白",
        ));
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(RMailError::InvalidServer("服务器域名标签无效"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_personal_data() {
        let config = AccountConfig::new(
            "profile-id".into(),
            "alice@example.com".into(),
            "correct horse battery staple".into(),
            MailServer::new("imap.example.com".into(), 993, TransportSecurity::Tls)
                .expect("valid incoming server"),
            MailServer::new("smtp.example.com".into(), 465, TransportSecurity::Tls)
                .expect("valid outgoing server"),
            DiscoveryMethod::Guessed,
        )
        .expect("valid account");

        let debug = format!("{config:?}");
        assert!(!debug.contains("alice@example.com"));
        assert!(!debug.contains("correct horse"));
    }

    #[test]
    fn server_rejects_unsafe_host_and_zero_port() {
        assert!(MailServer::new("bad host".into(), 993, TransportSecurity::Tls).is_err());
        assert!(MailServer::new("imap.example.com".into(), 0, TransportSecurity::Tls).is_err());
    }
}
