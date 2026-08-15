use crate::account::{DiscoveryMethod, MailServer, TransportSecurity};
use crate::{RMailError, Result};

#[derive(Debug, Eq, PartialEq)]
pub struct DiscoveredServers {
    pub incoming: MailServer,
    pub outgoing: MailServer,
    pub method: DiscoveryMethod,
}

pub fn discover(email: &str) -> Result<DiscoveredServers> {
    let domain = email_domain(email)?;
    let preset = match domain.as_str() {
        "gmail.com" | "googlemail.com" => Some((
            ("imap.gmail.com", 993, TransportSecurity::Tls),
            ("smtp.gmail.com", 465, TransportSecurity::Tls),
        )),
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" => Some((
            ("outlook.office365.com", 993, TransportSecurity::Tls),
            ("smtp-mail.outlook.com", 587, TransportSecurity::StartTls),
        )),
        "qq.com" => Some((
            ("imap.qq.com", 993, TransportSecurity::Tls),
            ("smtp.qq.com", 465, TransportSecurity::Tls),
        )),
        "163.com" => Some((
            ("imap.163.com", 993, TransportSecurity::Tls),
            ("smtp.163.com", 465, TransportSecurity::Tls),
        )),
        "126.com" => Some((
            ("imap.126.com", 993, TransportSecurity::Tls),
            ("smtp.126.com", 465, TransportSecurity::Tls),
        )),
        "icloud.com" | "me.com" | "mac.com" => Some((
            ("imap.mail.me.com", 993, TransportSecurity::Tls),
            ("smtp.mail.me.com", 587, TransportSecurity::StartTls),
        )),
        "yahoo.com" | "yahoo.co.jp" | "yahoo.co.uk" => Some((
            ("imap.mail.yahoo.com", 993, TransportSecurity::Tls),
            ("smtp.mail.yahoo.com", 465, TransportSecurity::Tls),
        )),
        _ => None,
    };

    let (incoming, outgoing, method) = if let Some((incoming, outgoing)) = preset {
        (incoming, outgoing, DiscoveryMethod::Preset)
    } else {
        let incoming = (format!("imap.{domain}"), 993, TransportSecurity::Tls);
        let outgoing = (format!("smtp.{domain}"), 465, TransportSecurity::Tls);
        return Ok(DiscoveredServers {
            incoming: MailServer::new(incoming.0, incoming.1, incoming.2)?,
            outgoing: MailServer::new(outgoing.0, outgoing.1, outgoing.2)?,
            method: DiscoveryMethod::Guessed,
        });
    };

    Ok(DiscoveredServers {
        incoming: MailServer::new(incoming.0.into(), incoming.1, incoming.2)?,
        outgoing: MailServer::new(outgoing.0.into(), outgoing.1, outgoing.2)?,
        method,
    })
}

pub fn email_domain(email: &str) -> Result<String> {
    if email.is_empty() || email.len() > 254 || email.trim() != email {
        return Err(RMailError::InvalidEmail("长度无效或首尾包含空白"));
    }
    let (local, domain) = email
        .rsplit_once('@')
        .ok_or(RMailError::InvalidEmail("缺少 @ 和域名"))?;
    if local.is_empty()
        || local.len() > 64
        || local.contains('@')
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || local.chars().any(char::is_control)
        || local.chars().any(char::is_whitespace)
    {
        return Err(RMailError::InvalidEmail("本地部分无效"));
    }
    let domain = domain.to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || !domain.is_ascii()
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(RMailError::InvalidEmail(
            "域名无效；当前 CLI 需要 ASCII 域名",
        ));
    }
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_known_provider() {
        let servers = discover("alice@gmail.com").expect("known provider");
        assert_eq!(servers.method, DiscoveryMethod::Preset);
        assert_eq!(servers.incoming.host, "imap.gmail.com");
        assert_eq!(servers.outgoing.host, "smtp.gmail.com");
    }

    #[test]
    fn guesses_unknown_provider() {
        let servers = discover("alice@example.org").expect("valid unknown provider");
        assert_eq!(servers.method, DiscoveryMethod::Guessed);
        assert_eq!(servers.incoming.host, "imap.example.org");
        assert_eq!(servers.outgoing.host, "smtp.example.org");
    }

    #[test]
    fn rejects_invalid_email_addresses() {
        for email in [
            "",
            "missing-at.example",
            "a@@example.com",
            ".a@example.com",
            "a@localhost",
        ] {
            assert!(discover(email).is_err(), "{email} should be rejected");
        }
    }
}
