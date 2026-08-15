use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};

use crate::account::{AccountConfig, MailServer, TransportSecurity};
use crate::mail::EmailDraft;
use crate::mail::mime::build_message;
use crate::{RMailError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendReceipt {
    pub accepted: bool,
}

pub fn send(
    account: &AccountConfig,
    server: &MailServer,
    draft: &EmailDraft,
) -> Result<SendReceipt> {
    let message = build_message(draft)?;
    let builder = match server.security {
        TransportSecurity::Tls => SmtpTransport::relay(&server.host),
        TransportSecurity::StartTls => SmtpTransport::starttls_relay(&server.host),
    }
    .map_err(|_| RMailError::Protocol("SMTP TLS 配置无效"))?
    .port(server.port)
    .credentials(Credentials::new(
        account.email.to_string(),
        account.password.to_string(),
    ));
    let transport = builder.build();
    transport
        .send(&message)
        .map_err(|_| RMailError::Protocol("SMTP 发送失败；请检查服务器、凭据与 TLS 设置"))?;
    Ok(SendReceipt { accepted: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_supported_security_modes_build_strict_tls_transport() {
        for security in [TransportSecurity::Tls, TransportSecurity::StartTls] {
            let server = MailServer {
                host: "smtp.example.com".into(),
                port: 465,
                security,
            };
            let result = match server.security {
                TransportSecurity::Tls => SmtpTransport::relay(&server.host),
                TransportSecurity::StartTls => SmtpTransport::starttls_relay(&server.host),
            };
            assert!(result.is_ok());
        }
    }
}
