use native_tls::TlsConnector;

use crate::account::{AccountConfig, MailServer, TransportSecurity};
use crate::mail::mime::parse_message;
use crate::mail::{MessageSource, ReceivedMessage};
use crate::{RMailError, Result};

pub const MAX_RECEIVE_LIMIT: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImapReceiveRequest {
    pub server: MailServer,
    pub mailbox: String,
    pub limit: usize,
    pub full: bool,
}

pub fn receive(
    account: &AccountConfig,
    request: &ImapReceiveRequest,
) -> Result<Vec<ReceivedMessage>> {
    validate_request(request)?;
    let tls = TlsConnector::builder()
        .build()
        .map_err(|_| RMailError::Protocol("无法配置 IMAP TLS"))?;
    let client = match request.server.security {
        TransportSecurity::Tls => imap::connect(
            (request.server.host.as_str(), request.server.port),
            &request.server.host,
            &tls,
        ),
        TransportSecurity::StartTls => imap::connect_starttls(
            (request.server.host.as_str(), request.server.port),
            &request.server.host,
            &tls,
        ),
    }
    .map_err(|_| RMailError::Protocol("无法建立受 TLS 保护的 IMAP 连接"))?;
    let mut session = client
        .login(&account.email, &account.password)
        .map_err(|_| RMailError::Protocol("IMAP 认证失败"))?;
    session
        .examine(&request.mailbox)
        .map_err(|_| RMailError::Protocol("无法以只读方式打开 IMAP 邮箱"))?;
    let mut ids: Vec<_> = session
        .search("ALL")
        .map_err(|_| RMailError::Protocol("无法列出 IMAP 邮件"))?
        .into_iter()
        .collect();
    ids.sort_unstable();
    let selected: Vec<_> = ids.into_iter().rev().take(request.limit).collect();
    if selected.is_empty() {
        session
            .logout()
            .map_err(|_| RMailError::Protocol("无法正常关闭 IMAP 会话"))?;
        return Ok(Vec::new());
    }
    let sequence_set = selected
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let query = if request.full {
        "(UID FLAGS RFC822.SIZE BODY.PEEK[])"
    } else {
        "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER])"
    };
    let fetched = session
        .fetch(sequence_set, query)
        .map_err(|_| RMailError::Protocol("无法读取 IMAP 邮件"))?;
    let mut messages = Vec::with_capacity(fetched.len());
    for fetch in &fetched {
        let raw = if request.full {
            fetch.body()
        } else {
            fetch.header()
        }
        .ok_or(RMailError::Protocol("IMAP 服务器未返回请求的邮件数据"))?;
        let mut message = parse_message(
            MessageSource::Imap {
                uid: fetch.uid,
                sequence: fetch.message,
            },
            raw,
            request.full,
        )?;
        message.size = fetch.size;
        message.flags = fetch.flags().iter().map(ToString::to_string).collect();
        messages.push(message);
    }
    session
        .logout()
        .map_err(|_| RMailError::Protocol("无法正常关闭 IMAP 会话"))?;
    Ok(messages)
}

pub fn list_mailboxes(account: &AccountConfig, server: &MailServer) -> Result<Vec<String>> {
    let tls = TlsConnector::builder()
        .build()
        .map_err(|_| RMailError::Protocol("无法配置 IMAP TLS"))?;
    let client = match server.security {
        TransportSecurity::Tls => {
            imap::connect((server.host.as_str(), server.port), &server.host, &tls)
        }
        TransportSecurity::StartTls => {
            imap::connect_starttls((server.host.as_str(), server.port), &server.host, &tls)
        }
    }
    .map_err(|_| RMailError::Protocol("无法建立受 TLS 保护的 IMAP 连接"))?;
    let mut session = client
        .login(&account.email, &account.password)
        .map_err(|_| RMailError::Protocol("IMAP 认证失败"))?;
    let names = session
        .list(None, Some("*"))
        .map_err(|_| RMailError::Protocol("无法列出 IMAP 邮箱"))?;
    let result = names.iter().map(|name| name.name().to_owned()).collect();
    session
        .logout()
        .map_err(|_| RMailError::Protocol("无法正常关闭 IMAP 会话"))?;
    Ok(result)
}

fn validate_request(request: &ImapReceiveRequest) -> Result<()> {
    if request.limit == 0 || request.limit > MAX_RECEIVE_LIMIT {
        return Err(RMailError::InvalidMessage(
            "IMAP 接收数量必须在 1 到 100 之间",
        ));
    }
    if request.mailbox.is_empty() || request.mailbox.contains(['\r', '\n', '\0']) {
        return Err(RMailError::InvalidMessage("IMAP 邮箱名称无效"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_mailbox_and_excessive_limit() {
        let server = MailServer {
            host: "imap.example.com".into(),
            port: 993,
            security: TransportSecurity::Tls,
        };
        assert!(
            validate_request(&ImapReceiveRequest {
                server: server.clone(),
                mailbox: "INBOX\r\nDELETE".into(),
                limit: 1,
                full: false
            })
            .is_err()
        );
        assert!(
            validate_request(&ImapReceiveRequest {
                server,
                mailbox: "INBOX".into(),
                limit: 101,
                full: false
            })
            .is_err()
        );
    }
}
