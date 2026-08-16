use crate::account::{MailServer, TransportSecurity};
use crate::key_store::KeyStore;
use crate::mail::{EmailDraft, ReceivedMessage};
use crate::protocol::{imap, pop3, smtp};
use crate::storage::AccountRepository;
use crate::{RMailError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveProtocol {
    Imap,
    Pop3,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServerOverride {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub security: Option<TransportSecurity>,
}

pub struct MailService<'a, K> {
    repository: &'a AccountRepository<K>,
}

impl<'a, K: KeyStore> MailService<'a, K> {
    pub fn new(repository: &'a AccountRepository<K>) -> Self {
        Self { repository }
    }

    pub fn send(
        &self,
        profile: &str,
        override_server: ServerOverride,
        draft: &EmailDraft,
    ) -> Result<smtp::SendReceipt> {
        let account = self.repository.load(profile)?;
        smtp::send(
            &account,
            &resolve_server(account.outgoing(), override_server)?,
            draft,
        )
    }

    pub fn receive(
        &self,
        profile: &str,
        protocol: ReceiveProtocol,
        override_server: ServerOverride,
        mailbox: String,
        limit: usize,
        full: bool,
    ) -> Result<Vec<ReceivedMessage>> {
        let account = self.repository.load(profile)?;
        match protocol {
            ReceiveProtocol::Imap => imap::receive(
                &account,
                &imap::ImapReceiveRequest {
                    server: resolve_server(account.incoming(), override_server)?,
                    mailbox,
                    limit,
                    full,
                },
            ),
            ReceiveProtocol::Pop3 => {
                let host = override_server
                    .host
                    .clone()
                    .ok_or(RMailError::InvalidServer(
                        "使用 POP3 时必须通过 --server 指定 POP3 服务器",
                    ))?;
                let server = resolve_server(
                    &MailServer {
                        host,
                        port: 995,
                        security: TransportSecurity::Tls,
                    },
                    override_server,
                )?;
                pop3::receive(
                    &account,
                    &pop3::Pop3ReceiveRequest {
                        server,
                        limit,
                        full,
                    },
                )
            }
        }
    }

    pub fn remote_mailboxes(
        &self,
        profile: &str,
        override_server: ServerOverride,
    ) -> Result<Vec<String>> {
        let account = self.repository.load(profile)?;
        imap::list_mailboxes(
            &account,
            &resolve_server(account.incoming(), override_server)?,
        )
    }
}

fn resolve_server(default: &MailServer, override_server: ServerOverride) -> Result<MailServer> {
    MailServer::new(
        override_server.host.unwrap_or_else(|| default.host.clone()),
        override_server.port.unwrap_or(default.port),
        override_server.security.unwrap_or(default.security),
    )
}
