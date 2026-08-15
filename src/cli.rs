use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

use crate::account::{DiscoveryMethod, MailServer, TransportSecurity};
use crate::key_store::OsKeyStore;
use crate::mail::{Attachment, EmailAddress, EmailDraft, MessagePriority};
use crate::mail_service::{MailService, ReceiveProtocol, ServerOverride};
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
    /// 解密并列出已保存账号；不会显示密码。
    List,
    /// 解密并显示一个账号；不会显示密码。
    Show {
        /// 配置 ID；仅有一个账号时可省略。
        profile_id: Option<String>,
    },
    /// 显示模块化数据根目录。
    Path,
}

pub fn run(cli: Cli) -> Result<()> {
    let paths = match cli.data_dir {
        Some(root) => DataPaths::from_root(root),
        None => DataPaths::system_default()?,
    };
    let repository = AccountRepository::new(paths, OsKeyStore);

    match cli.command {
        Command::Config(config) => match config.action {
            ConfigAction::Add => add_account(&repository),
            ConfigAction::List => list_accounts(&repository),
            ConfigAction::Show { profile_id } => show_account(&repository, profile_id.as_deref()),
            ConfigAction::Path => {
                println!("{}", repository.paths().root.display());
                Ok(())
            }
        },
        Command::Send(args) => send_mail(&repository, *args),
        Command::Receive(args) => receive_mail(&repository, args),
    }
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
    println!("邮件已由 SMTP 服务器接受。");
    Ok(())
}

fn receive_mail(repository: &AccountRepository<OsKeyStore>, args: ReceiveArgs) -> Result<()> {
    let messages = MailService::new(repository).receive(
        &args.account,
        args.protocol.into(),
        ServerOverride {
            host: args.server,
            port: args.port,
            security: args.security.map(Into::into),
        },
        args.mailbox,
        args.limit,
        args.full,
    )?;
    for message in messages {
        println!(
            "来源：{:?}\n主题：{}\n发件人：{}\n大小：{}\n",
            message.source,
            message.envelope.subject.unwrap_or_default(),
            message
                .envelope
                .from
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            message.size.unwrap_or_default()
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn parses_supported_config_commands() {
        assert!(Cli::try_parse_from(["RMail", "config", "add"]).is_ok());
        assert!(Cli::try_parse_from(["RMail", "config", "list"]).is_ok());
        assert!(Cli::try_parse_from(["RMail", "config", "show"]).is_ok());
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
    fn requires_a_subcommand() {
        assert!(Cli::try_parse_from(["RMail"]).is_err());
        assert!(Cli::try_parse_from(["RMail", "config"]).is_err());
    }
}
