use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use native_tls::{TlsConnector, TlsStream};

use crate::account::{AccountConfig, MailServer, TransportSecurity};
use crate::mail::mime::parse_message;
use crate::mail::{MessageSource, ReceivedMessage};
use crate::{RMailError, Result};

const MAX_RESPONSE_LINE: usize = 8 * 1024;
const MAX_MESSAGE_BYTES: usize = 30 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pop3ReceiveRequest {
    pub server: MailServer,
    pub limit: usize,
    pub full: bool,
}

pub fn receive(
    account: &AccountConfig,
    request: &Pop3ReceiveRequest,
) -> Result<Vec<ReceivedMessage>> {
    if request.limit == 0 || request.limit > super::imap::MAX_RECEIVE_LIMIT {
        return Err(RMailError::InvalidMessage(
            "POP3 接收数量必须在 1 到 100 之间",
        ));
    }
    let mut session = Pop3Session::connect(&request.server)?;
    session.login(&account.email, &account.password)?;
    let mut rows = session.list()?;
    rows.sort_by_key(|(number, _)| *number);
    let selected: Vec<_> = rows.into_iter().rev().take(request.limit).collect();
    let uidls = session.uidl()?;
    let mut messages = Vec::with_capacity(selected.len());
    for (number, size) in selected.into_iter().rev() {
        let raw = if request.full {
            session.multiline(&format!("RETR {number}"))?
        } else {
            session.multiline(&format!("TOP {number} 0"))?
        };
        let mut message = parse_message(
            MessageSource::Pop3 {
                number,
                uidl: uidls.get(&number).cloned(),
            },
            &raw,
            request.full,
        )?;
        message.size = Some(size);
        messages.push(message);
    }
    session.quit()?;
    Ok(messages)
}

struct Pop3Session {
    stream: BufReader<TlsStream<TcpStream>>,
}

impl Pop3Session {
    fn connect(server: &MailServer) -> Result<Self> {
        let stream = TcpStream::connect((server.host.as_str(), server.port))
            .map_err(|_| RMailError::Protocol("无法连接 POP3 服务器"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|_| RMailError::Protocol("无法设置 POP3 读取超时"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|_| RMailError::Protocol("无法设置 POP3 写入超时"))?;
        let tls = TlsConnector::builder()
            .build()
            .map_err(|_| RMailError::Protocol("无法配置 POP3 TLS"))?;
        match server.security {
            TransportSecurity::Tls => {
                let stream = tls
                    .connect(&server.host, stream)
                    .map_err(|_| RMailError::Protocol("POP3 TLS 握手失败"))?;
                let mut session = Self {
                    stream: BufReader::new(stream),
                };
                session.read_ok()?;
                Ok(session)
            }
            TransportSecurity::StartTls => Self::upgrade_starttls(server, tls, stream),
        }
    }

    fn upgrade_starttls(server: &MailServer, tls: TlsConnector, stream: TcpStream) -> Result<Self> {
        let mut plain = BufReader::new(stream);
        read_ok_line(&mut plain)?;
        write_command(plain.get_mut(), "STLS")?;
        read_ok_line(&mut plain)?;
        let stream = tls
            .connect(&server.host, plain.into_inner())
            .map_err(|_| RMailError::Protocol("POP3 STARTTLS 握手失败"))?;
        Ok(Self {
            stream: BufReader::new(stream),
        })
    }

    fn login(&mut self, user: &str, password: &str) -> Result<()> {
        reject_command_value(user)?;
        reject_command_value(password)?;
        self.command(&format!("USER {user}"))?;
        self.command(&format!("PASS {password}"))
    }

    fn list(&mut self) -> Result<Vec<(u32, u32)>> {
        let lines = self.multiline("LIST")?;
        Ok(lines
            .split(|byte| *byte == b'\n')
            .filter_map(|line| std::str::from_utf8(line).ok())
            .filter_map(|line| {
                let mut values = line.split_ascii_whitespace();
                Some((values.next()?.parse().ok()?, values.next()?.parse().ok()?))
            })
            .collect::<Vec<_>>())
    }

    fn uidl(&mut self) -> Result<std::collections::BTreeMap<u32, String>> {
        let lines = self.multiline("UIDL")?;
        let mut ids = std::collections::BTreeMap::new();
        for line in lines.split(|byte| *byte == b'\n') {
            let Ok(line) = std::str::from_utf8(line) else {
                continue;
            };
            let mut values = line.split_ascii_whitespace();
            if let (Some(number), Some(uidl)) = (values.next(), values.next())
                && let Ok(number) = number.parse()
            {
                ids.insert(number, uidl.to_owned());
            }
        }
        Ok(ids)
    }

    fn command(&mut self, command: &str) -> Result<()> {
        write_command(self.stream.get_mut(), command)?;
        self.read_ok()
    }

    fn multiline(&mut self, command: &str) -> Result<Vec<u8>> {
        write_command(self.stream.get_mut(), command)?;
        self.read_ok()?;
        read_multiline(&mut self.stream)
    }

    fn read_ok(&mut self) -> Result<()> {
        read_ok_line(&mut self.stream)
    }

    fn quit(&mut self) -> Result<()> {
        self.command("QUIT")
    }
}

fn reject_command_value(value: &str) -> Result<()> {
    if value.is_empty() || value.contains(['\r', '\n', '\0']) {
        return Err(RMailError::InvalidMessage("POP3 认证字段无效"));
    }
    Ok(())
}

fn write_command(stream: &mut impl Write, command: &str) -> Result<()> {
    if command.contains(['\r', '\n', '\0']) {
        return Err(RMailError::InvalidMessage("POP3 命令无效"));
    }
    stream
        .write_all(command.as_bytes())
        .and_then(|_| stream.write_all(b"\r\n"))
        .and_then(|_| stream.flush())
        .map_err(|_| RMailError::Protocol("POP3 命令发送失败"))
}

fn read_ok_line(reader: &mut impl BufRead) -> Result<()> {
    let line = read_line_limited(reader)?;
    if line.starts_with(b"+OK") {
        Ok(())
    } else {
        Err(RMailError::Protocol("POP3 服务器拒绝了请求"))
    }
}

fn read_multiline(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let mut line = read_line_limited(reader)?;
        if line == b".\r\n" || line == b".\n" {
            return Ok(output);
        }
        if line.starts_with(b"..") {
            line.remove(0);
        }
        if output.len().saturating_add(line.len()) > MAX_MESSAGE_BYTES {
            return Err(RMailError::Protocol("POP3 响应超过大小限制"));
        }
        output.extend_from_slice(&line);
    }
}

fn read_line_limited(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    let count = reader
        .read_until(b'\n', &mut line)
        .map_err(|_| RMailError::Protocol("POP3 响应读取失败"))?;
    if count == 0 || line.len() > MAX_RESPONSE_LINE || !line.ends_with(b"\n") {
        return Err(RMailError::Protocol("POP3 响应行无效或过长"));
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn unescapes_dot_stuffed_response_without_deletion() {
        let mut input = Cursor::new(b"..dot\r\nnormal\r\n.\r\n".to_vec());
        assert_eq!(
            read_multiline(&mut input).expect("response"),
            b".dot\r\nnormal\r\n"
        );
        assert!(reject_command_value("user\r\nDELE 1").is_err());
    }
}
