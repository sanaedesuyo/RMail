use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

use crate::account::{DiscoveryMethod, MailServer, TransportSecurity};
use crate::key_store::OsKeyStore;
use crate::logging::{LogLevel, Logger};
use crate::mail::{Attachment, EmailAddress, EmailDraft, MessagePriority};
use crate::mail_service::{MailService, ReceiveProtocol, ServerOverride};
use crate::mail_store::{LocalMailbox, MailStore};
use crate::server::{DiscoveredServers, discover};
use crate::service::AccountService;
use crate::storage::{AccountRepository, DataPaths};
use crate::{RMailError, Result};

#[derive(Debug, Parser)]
#[command(name = "RMail", version, about = "安全、跨平台的邮件客户端 CLI")]
pub struct Cli {
    /// 覆盖系统默认数据目录，主要用于隔离环境与调试。
    #[arg(long, global = true, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 管理加密的用户配置。
    Config(ConfigArgs),
    /// 通过已配置账号安全发送邮件。
    Send(Box<SendArgs>),
    /// 从 IMAP 或 POP3 邮箱接收邮件；默认仅下载邮件头。
    Receive(ReceiveArgs),
    /// 管理本地加密保存的邮件。
    Mail(MailArgs),
}

#[derive(Debug, Args)]
pub struct SendArgs {
    #[arg(long)]
    pub account: String,
    #[arg(long, required = true, value_delimiter = ',')]
    pub to: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    pub cc: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    pub bcc: Vec<String>,
    #[arg(long)]
    pub subject: String,
    /// 正文文件。避免把敏感正文放入 shell 历史记录。
    #[arg(long, value_name = "PATH")]
    pub text_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub html_file: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub attachment: Vec<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub inline_attachment: Vec<PathBuf>,
    #[arg(long)]
    pub reply_to: Option<String>,
    #[arg(long)]
    pub in_reply_to: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub reference: Vec<String>,
    #[arg(long)]
    pub smtp_server: Option<String>,
    #[arg(long)]
    pub smtp_port: Option<u16>,
    #[arg(long, value_enum)]
    pub smtp_security: Option<SecurityArg>,
}

#[derive(Debug, Args)]
pub struct ReceiveArgs {
    #[arg(long)]
    pub account: String,
    #[arg(long, value_enum, default_value_t = ReceiveProtocolArg::Imap)]
    pub protocol: ReceiveProtocolArg,
    /// POP3 必填；IMAP 不填时使用账号配置中的服务器。
    #[arg(long)]
    pub server: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long, value_enum)]
    pub security: Option<SecurityArg>,
    #[arg(long, default_value = "INBOX")]
    pub mailbox: String,
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
    /// 下载正文和附件到内存；不会将其持久化。
    #[arg(long)]
    pub full: bool,
}

#[derive(Debug, Args)]
pub struct MailArgs {
    #[command(subcommand)]
    pub action: MailAction,
}
#[derive(Debug, Subcommand)]
pub enum MailAction {
    /// 列出账户邮件或本地逻辑邮箱。
    List {
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        mailbox: Option<String>,
        #[arg(long, value_enum)]
        local: Option<LocalMailboxArg>,
    },
    /// 将邮件移入本地回收站。
    Delete {
        #[arg(long)]
        account: String,
        message_id: String,
    },
    /// 从本地回收站恢复邮件至原邮件箱。
    Restore {
        #[arg(long)]
        account: String,
        message_id: String,
    },
    /// 立即永久删除回收站中的邮件；必须提供相同邮件 ID 再次确认。
    Purge {
        #[arg(long)]
        account: String,
        message_id: String,
        #[arg(long)]
        confirm: String,
    },
}
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LocalMailboxArg {
    New,
    Sent,
    Trash,
    Starred,
}
impl From<LocalMailboxArg> for LocalMailbox {
    fn from(value: LocalMailboxArg) -> Self {
        match value {
            LocalMailboxArg::New => Self::New,
            LocalMailboxArg::Sent => Self::Sent,
            LocalMailboxArg::Trash => Self::Trash,
            LocalMailboxArg::Starred => Self::Starred,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SecurityArg {
    Tls,
    Starttls,
}
impl From<SecurityArg> for TransportSecurity {
    fn from(value: SecurityArg) -> Self {
        match value {
            SecurityArg::Tls => Self::Tls,
            SecurityArg::Starttls => Self::StartTls,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum ReceiveProtocolArg {
    #[default]
    Imap,
    Pop3,
}
impl From<ReceiveProtocolArg> for ReceiveProtocol {
    fn from(value: ReceiveProtocolArg) -> Self {
        match value {
            ReceiveProtocolArg::Imap => Self::Imap,
            ReceiveProtocolArg::Pop3 => Self::Pop3,
        }
    }
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// 交互式添加邮箱账号。
    Add,
    /// 交互式更新账号信息；留空的字段保持不变。
    Update {
        /// 要更新的配置 ID。
        profile_id: String,
    },
    /// 删除账号配置及其系统凭据库密钥；需要二次确认。
    Delete {
        /// 要删除的配置 ID。
        profile_id: String,
    },
    /// 解密并列出已保存账号；不会显示密码。
    List,
    /// 解密并显示一个账号；不会显示密码。
    Show {
        /// 配置 ID；仅有一个账号时可省略。
        profile_id: Option<String>,
    },
    /// 显示模块化数据根目录。
    Path,
    /// 设置日志最多保留的条目数（默认 1000）。
    LogLimit {
        /// 1 到 100000；达到上限时淘汰最旧日志。
        max_entries: usize,
    },
}

pub fn run(cli: Cli) -> Result<()> {
    let paths = match cli.data_dir {
        Some(root) => DataPaths::from_root(root),
        None => DataPaths::system_default()?,
    };
    let logger = Logger::new(paths.clone(), OsKeyStore);
    let repository = AccountRepository::new(paths, OsKeyStore);

    let outcome = match cli.command {
        Command::Config(config) => match config.action {
            ConfigAction::Add => add_account(&repository),
            ConfigAction::Update { profile_id } => update_account(&repository, &profile_id),
            ConfigAction::Delete { profile_id } => delete_account(&repository, &profile_id),
            ConfigAction::List => list_accounts(&repository),
            ConfigAction::Show { profile_id } => show_account(&repository, profile_id.as_deref()),
            ConfigAction::Path => {
                println!("{}", repository.paths().root.display());
                Ok(())
            }
            ConfigAction::LogLimit { max_entries } => set_log_limit(&logger, max_entries),
        },
        Command::Send(args) => send_mail(&repository, *args),
        Command::Receive(args) => receive_mail(&repository, args),
        Command::Mail(args) => manage_mail(&repository, args),
    };
    let log_result = logger.record(
        if outcome.is_ok() {
            LogLevel::Info
        } else {
            LogLevel::Error
        },
        if outcome.is_ok() {
            "cli.command_completed"
        } else {
            "cli.command_failed"
        },
    );
    match (outcome, log_result) {
        (Ok(()), Err(error)) => Err(error),
        (result, _) => result,
    }
}

fn set_log_limit(logger: &Logger<OsKeyStore>, max_entries: usize) -> Result<()> {
    logger.set_max_entries(max_entries)?;
    let log_path = logger.log_path();
    println!(
        "日志条目上限已设置为 {max_entries}。日志目录：{}",
        log_path.parent().unwrap_or(&log_path).display()
    );
    Ok(())
}

fn send_mail(repository: &AccountRepository<OsKeyStore>, args: SendArgs) -> Result<()> {
    let draft = EmailDraft {
        from: EmailAddress::new(None, repository.load(&args.account)?.email().to_owned())?,
        to: parse_addresses(args.to)?,
        cc: parse_addresses(args.cc)?,
        bcc: parse_addresses(args.bcc)?,
        reply_to: args
            .reply_to
            .map(|value| EmailAddress::new(None, value))
            .transpose()?,
        subject: args.subject,
        text_body: read_optional_secret_file(args.text_file)?,
        html_body: read_optional_secret_file(args.html_file)?,
        attachments: read_attachments(args.attachment, false)?,
        in_reply_to: args.in_reply_to,
        references: args.reference,
        priority: MessagePriority::Normal,
    };
    let mut attachments = draft.attachments;
    attachments.extend(read_attachments(args.inline_attachment, true)?);
    let draft = EmailDraft {
        attachments,
        ..draft
    };
    MailService::new(repository).send(
        &args.account,
        ServerOverride {
            host: args.smtp_server,
            port: args.smtp_port,
            security: args.smtp_security.map(Into::into),
        },
        &draft,
    )?;
    MailStore::new(repository.paths().clone(), OsKeyStore).save_sent(
        &args.account,
        crate::mail::mime::build_message(&draft)?.formatted(),
    )?;
    println!("邮件已由 SMTP 服务器接受。");
    Ok(())
}

fn receive_mail(repository: &AccountRepository<OsKeyStore>, args: ReceiveArgs) -> Result<()> {
    let override_server = ServerOverride {
        host: args.server,
        port: args.port,
        security: args.security.map(Into::into),
    };
    let service = MailService::new(repository);
    let mailbox = args.mailbox.clone();
    let messages = service.receive(
        &args.account,
        args.protocol.into(),
        override_server.clone(),
        mailbox.clone(),
        args.limit,
        args.full,
    )?;
    let store = MailStore::new(repository.paths().clone(), OsKeyStore);
    if matches!(args.protocol, ReceiveProtocolArg::Imap) {
        store.sync_mailboxes(
            &args.account,
            service.remote_mailboxes(&args.account, override_server)?,
        )?;
    } else {
        store.sync_mailboxes(&args.account, ["INBOX".into()])?;
    }
    store.save_received(&args.account, &mailbox, messages)?;
    let messages = store.list_account(&args.account, Some(&mailbox))?;
    for message in messages {
        println!(
            "邮件 ID：{}\n邮件箱：{}\n未读：{}\n星标：{}\n",
            message.message_id, message.mailbox, message.unread, message.starred
        );
    }
    Ok(())
}

fn manage_mail(repository: &AccountRepository<OsKeyStore>, args: MailArgs) -> Result<()> {
    let store = MailStore::new(repository.paths().clone(), OsKeyStore);
    match args.action {
        MailAction::List {
            account,
            mailbox,
            local,
        } => {
            let messages = match (account, local) {
                (Some(account), None) => store.list_account(&account, mailbox.as_deref())?,
                (None, Some(local)) => {
                    store.list_local(&repository.list_profile_ids()?, local.into())?
                }
                _ => {
                    return Err(RMailError::InvalidChoice(
                        "请指定 --account，或指定一个 --local 邮件箱",
                    ));
                }
            };
            for message in messages {
                println!(
                    "{}  {}  {}  未读:{}  星标:{}",
                    message.account_id,
                    message.message_id,
                    message.mailbox,
                    message.unread,
                    message.starred
                );
            }
            Ok(())
        }
        MailAction::Delete {
            account,
            message_id,
        } => store.delete(&account, &message_id),
        MailAction::Restore {
            account,
            message_id,
        } => store.restore(&account, &message_id),
        MailAction::Purge {
            account,
            message_id,
            confirm,
        } => {
            if confirm != message_id {
                return Err(RMailError::InvalidChoice(
                    "确认邮件 ID 不匹配，已取消永久删除",
                ));
            }
            store.purge(&account, &message_id)
        }
    }
}

fn parse_addresses(values: Vec<String>) -> Result<Vec<EmailAddress>> {
    values
        .into_iter()
        .map(|value| EmailAddress::new(None, value))
        .collect()
}
fn read_optional_secret_file(path: Option<PathBuf>) -> Result<Option<Zeroizing<String>>> {
    path.map(|path| {
        std::fs::read_to_string(&path)
            .map(Zeroizing::new)
            .map_err(|source| RMailError::Io {
                action: "读取正文文件",
                path,
                source,
            })
    })
    .transpose()
}
fn read_attachments(paths: Vec<PathBuf>, inline: bool) -> Result<Vec<Attachment>> {
    paths
        .iter()
        .map(|path| Attachment::from_path(path, inline))
        .collect()
}

fn add_account(repository: &AccountRepository<OsKeyStore>) -> Result<()> {
    let email = prompt_line("邮箱地址：")?;
    let discovered = discover(&email)?;
    print_discovered_servers(&discovered);
    let (incoming, outgoing, method) = select_servers(discovered)?;

    let password = Zeroizing::new(
        rpassword::prompt_password("邮箱密码或应用专用密码（输入内容不会回显）：")
            .map_err(RMailError::Input)?,
    );
    if password.is_empty() {
        return Err(RMailError::EmptyPassword);
    }

    let profile_id = AccountService::new(repository).create(
        email,
        password.to_string(),
        incoming,
        outgoing,
        method,
    )?;
    println!("账号配置已加密保存。配置 ID：{profile_id}");
    println!("数据根目录：{}", repository.paths().root.display());
    Ok(())
}

fn update_account(repository: &AccountRepository<OsKeyStore>, profile_id: &str) -> Result<()> {
    let current = repository.load(profile_id)?;
    println!("正在更新账号 {}（留空表示保持原值）。", current.email());
    let email = optional_prompt_line("新邮箱地址：")?;
    let password = Zeroizing::new(
        rpassword::prompt_password("新邮箱密码或应用专用密码（留空保持原值，不会回显）：")
            .map_err(RMailError::Input)?,
    );
    let password = (!password.is_empty()).then_some(password);
    let change_servers = prompt_line("更新 IMAP/SMTP 服务器配置？[y/N]：")?;
    let (incoming, outgoing, discovery) = match change_servers.to_ascii_lowercase().as_str() {
        "" | "n" | "no" => (None, None, None),
        "y" | "yes" => {
            let incoming = prompt_server("IMAP", current.incoming().port)?;
            let outgoing = prompt_server("SMTP", current.outgoing().port)?;
            (
                Some(incoming),
                Some(outgoing),
                Some(DiscoveryMethod::Manual),
            )
        }
        _ => return Err(RMailError::InvalidChoice("请输入 Y 或 N")),
    };
    AccountService::new(repository)
        .update(profile_id, email, password, incoming, outgoing, discovery)?;
    println!("账号配置已更新并重新加密保存。");
    Ok(())
}

fn delete_account(repository: &AccountRepository<OsKeyStore>, profile_id: &str) -> Result<()> {
    let account = repository.load(profile_id)?;
    println!(
        "将删除账号 {} 的加密配置和系统凭据库密钥。",
        account.email()
    );
    let confirmation = prompt_line(&format!("请输入配置 ID {profile_id} 以确认删除："))?;
    if confirmation != profile_id {
        return Err(RMailError::InvalidChoice(
            "确认的配置 ID 不匹配，已取消删除",
        ));
    }
    AccountService::new(repository).delete(profile_id)?;
    println!("账号配置和系统凭据库密钥已删除。");
    Ok(())
}

fn list_accounts(repository: &AccountRepository<OsKeyStore>) -> Result<()> {
    let profile_ids = repository.list_profile_ids()?;
    if profile_ids.is_empty() {
        return Err(RMailError::NoProfiles);
    }
    for profile_id in profile_ids {
        let account = repository.load(&profile_id)?;
        println!(
            "{}  {}  {}",
            account.profile_id(),
            account.email(),
            account.discovery()
        );
    }
    Ok(())
}

fn show_account(
    repository: &AccountRepository<OsKeyStore>,
    requested_profile_id: Option<&str>,
) -> Result<()> {
    let profile_id = repository.resolve_profile(requested_profile_id)?;
    let account = repository.load(&profile_id)?;
    println!("配置 ID：{}", account.profile_id());
    println!("邮箱地址：{}", account.email());
    println!("发现方式：{}", account.discovery());
    println!(
        "IMAP：{}:{} ({})",
        account.incoming().host,
        account.incoming().port,
        account.incoming().security
    );
    println!(
        "SMTP：{}:{} ({})",
        account.outgoing().host,
        account.outgoing().port,
        account.outgoing().security
    );
    println!("密码：[已成功解密，出于安全原因不显示]");
    Ok(())
}

fn print_discovered_servers(servers: &DiscoveredServers) {
    println!("服务器发现方式：{}", servers.method);
    println!(
        "  IMAP  {}:{} ({})",
        servers.incoming.host, servers.incoming.port, servers.incoming.security
    );
    println!(
        "  SMTP  {}:{} ({})",
        servers.outgoing.host, servers.outgoing.port, servers.outgoing.security
    );
    if servers.method == DiscoveryMethod::Guessed {
        println!("提示：这是按域名规则推断的结果，保存前请确认服务商文档。");
    }
}

fn select_servers(
    discovered: DiscoveredServers,
) -> Result<(MailServer, MailServer, DiscoveryMethod)> {
    let choice = prompt_line("使用以上配置？[Y] 使用 / [M] 手动输入：")?;
    match choice.to_ascii_lowercase().as_str() {
        "" | "y" | "yes" => Ok((discovered.incoming, discovered.outgoing, discovered.method)),
        "m" | "manual" => {
            let incoming = prompt_server("IMAP", 993)?;
            let outgoing = prompt_server("SMTP", 465)?;
            Ok((incoming, outgoing, DiscoveryMethod::Manual))
        }
        _ => Err(RMailError::InvalidChoice("请输入 Y 或 M")),
    }
}

fn prompt_server(label: &str, default_port: u16) -> Result<MailServer> {
    let host = prompt_line(&format!("{label} 服务器域名："))?;
    let port_text = prompt_line(&format!("{label} 端口（默认 {default_port}）："))?;
    let port = if port_text.is_empty() {
        default_port
    } else {
        port_text
            .parse::<u16>()
            .map_err(|_| RMailError::InvalidServer("端口必须是 1 到 65535 的整数"))?
    };
    let security_text = prompt_line(&format!(
        "{label} 传输安全：[1] TLS（默认） / [2] STARTTLS："
    ))?;
    let security = match security_text.to_ascii_lowercase().as_str() {
        "" | "1" | "tls" => TransportSecurity::Tls,
        "2" | "starttls" => TransportSecurity::StartTls,
        _ => return Err(RMailError::InvalidChoice("传输安全请输入 1 或 2")),
    };
    MailServer::new(host, port, security)
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().map_err(RMailError::Input)?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(RMailError::Input)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn optional_prompt_line(prompt: &str) -> Result<Option<String>> {
    let value = prompt_line(prompt)?;
    Ok((!value.is_empty()).then_some(value))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn parses_supported_config_commands() {
        assert!(Cli::try_parse_from(["RMail", "config", "add"]).is_ok());
        assert!(Cli::try_parse_from(["RMail", "config", "list"]).is_ok());
        assert!(Cli::try_parse_from(["RMail", "config", "show"]).is_ok());
        assert!(Cli::try_parse_from(["RMail", "config", "log-limit", "500"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "RMail",
                "config",
                "update",
                "94450d7f-6a4a-4cf4-b562-ae567104c425"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "RMail",
                "config",
                "delete",
                "94450d7f-6a4a-4cf4-b562-ae567104c425"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "RMail",
                "--data-dir",
                "isolated",
                "config",
                "show",
                "94450d7f-6a4a-4cf4-b562-ae567104c425"
            ])
            .is_ok()
        );
    }

    #[test]
    fn parses_send_and_receive_commands_without_password_arguments() {
        assert!(
            Cli::try_parse_from([
                "RMail",
                "send",
                "--account",
                "profile",
                "--to",
                "bob@example.com",
                "--subject",
                "Hello",
                "--text-file",
                "body.txt",
                "--smtp-security",
                "tls"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "RMail",
                "receive",
                "--account",
                "profile",
                "--protocol",
                "pop3",
                "--server",
                "pop.example.com",
                "--full"
            ])
            .is_ok()
        );
    }

    #[test]
    fn parses_mail_management_commands() {
        assert!(Cli::try_parse_from(["RMail", "mail", "list", "--local", "new"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "RMail",
                "mail",
                "delete",
                "--account",
                "94450d7f-6a4a-4cf4-b562-ae567104c425",
                "message-id"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "RMail",
                "mail",
                "purge",
                "--account",
                "94450d7f-6a4a-4cf4-b562-ae567104c425",
                "message-id",
                "--confirm",
                "message-id"
            ])
            .is_ok()
        );
    }

    #[test]
    fn requires_a_subcommand() {
        assert!(Cli::try_parse_from(["RMail"]).is_err());
        assert!(Cli::try_parse_from(["RMail", "config"]).is_err());
    }
}
