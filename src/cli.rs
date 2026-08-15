use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use crate::account::{DiscoveryMethod, MailServer, TransportSecurity};
use crate::key_store::OsKeyStore;
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
    }
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
    fn requires_a_subcommand() {
        assert!(Cli::try_parse_from(["RMail"]).is_err());
        assert!(Cli::try_parse_from(["RMail", "config"]).is_err());
    }
}
