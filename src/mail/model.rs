use std::fmt;
use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::{RMailError, Result};

pub const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct EmailAddress {
    pub display_name: Option<String>,
    pub address: String,
}

impl EmailAddress {
    pub fn new(display_name: Option<String>, address: String) -> Result<Self> {
        crate::server::email_domain(&address)?;
        if display_name
            .as_deref()
            .is_some_and(|name| name.is_empty() || contains_line_break(name))
        {
            return Err(RMailError::InvalidMessage("显示名称包含无效换行"));
        }
        Ok(Self {
            display_name,
            address,
        })
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.display_name {
            Some(name) => write!(formatter, "{name} <{}>", self.address),
            None => formatter.write_str(&self.address),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Authentication {
    Password,
    OAuth2Bearer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessagePriority {
    Low,
    Normal,
    High,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentDisposition {
    Attachment,
    Inline,
}

pub struct Attachment {
    pub filename: String,
    pub media_type: String,
    pub disposition: AttachmentDisposition,
    pub content_id: Option<String>,
    pub content: Zeroizing<Vec<u8>>,
}

impl Attachment {
    pub fn from_path(path: &Path, inline: bool) -> Result<Self> {
        let metadata = fs::metadata(path).map_err(|source| RMailError::Io {
            action: "读取附件元数据",
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.len() > MAX_ATTACHMENT_BYTES {
            return Err(RMailError::InvalidMessage("附件超过 25 MiB 限制"));
        }
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty() && !contains_line_break(name))
            .ok_or(RMailError::InvalidMessage("附件文件名无效"))?
            .to_owned();
        let content = fs::read(path).map_err(|source| RMailError::Io {
            action: "读取附件",
            path: path.to_path_buf(),
            source,
        })?;
        let media_type = mime_guess::from_path(path)
            .first_or_octet_stream()
            .essence_str()
            .to_owned();
        Ok(Self {
            filename,
            media_type,
            disposition: if inline {
                AttachmentDisposition::Inline
            } else {
                AttachmentDisposition::Attachment
            },
            content_id: None,
            content: Zeroizing::new(content),
        })
    }
}

impl fmt::Debug for Attachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Attachment")
            .field("filename", &self.filename)
            .field("media_type", &self.media_type)
            .field("disposition", &self.disposition)
            .field("content_id", &self.content_id)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

pub struct EmailDraft {
    pub from: EmailAddress,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub reply_to: Option<EmailAddress>,
    pub subject: String,
    pub text_body: Option<Zeroizing<String>>,
    pub html_body: Option<Zeroizing<String>>,
    pub attachments: Vec<Attachment>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub priority: MessagePriority,
}

impl EmailDraft {
    pub fn validate(&self) -> Result<()> {
        if self.to.is_empty() && self.cc.is_empty() && self.bcc.is_empty() {
            return Err(RMailError::InvalidMessage("至少需要一个收件人"));
        }
        if contains_line_break(&self.subject) {
            return Err(RMailError::InvalidMessage("主题不能包含换行"));
        }
        if self.in_reply_to.as_deref().is_some_and(contains_line_break)
            || self
                .references
                .iter()
                .any(|reference| contains_line_break(reference))
        {
            return Err(RMailError::InvalidMessage("邮件线程 ID 包含无效换行"));
        }
        for attachment in &self.attachments {
            if attachment.content.len() as u64 > MAX_ATTACHMENT_BYTES
                || contains_line_break(&attachment.filename)
                || contains_line_break(&attachment.media_type)
                || attachment
                    .content_id
                    .as_deref()
                    .is_some_and(contains_line_break)
            {
                return Err(RMailError::InvalidMessage("附件元数据或大小无效"));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for EmailDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailDraft")
            .field("from", &"[REDACTED]")
            .field("to", &format_args!("{} recipient(s)", self.to.len()))
            .field("cc", &format_args!("{} recipient(s)", self.cc.len()))
            .field("bcc", &format_args!("{} recipient(s)", self.bcc.len()))
            .field("subject", &"[REDACTED]")
            .field("text_body", &"[REDACTED]")
            .field("html_body", &"[REDACTED]")
            .field(
                "attachments",
                &format_args!("{} attachment(s)", self.attachments.len()),
            )
            .field("priority", &self.priority)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageSource {
    Imap { uid: Option<u32>, sequence: u32 },
    Pop3 { number: u32, uidl: Option<String> },
}

#[derive(Clone, Eq, PartialEq)]
pub struct MessageEnvelope {
    pub message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub subject: Option<String>,
    pub date_rfc3339: Option<String>,
    pub from: Vec<EmailAddress>,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub reply_to: Vec<EmailAddress>,
}

pub struct ReceivedAttachment {
    pub filename: Option<String>,
    pub media_type: Option<String>,
    pub content_id: Option<String>,
    pub size: usize,
    pub content: Option<Zeroizing<Vec<u8>>>,
}

pub struct MessageContent {
    pub text: Vec<Zeroizing<String>>,
    pub html: Vec<Zeroizing<String>>,
    pub attachments: Vec<ReceivedAttachment>,
}

pub struct ReceivedMessage {
    pub source: MessageSource,
    pub envelope: MessageEnvelope,
    pub size: Option<u32>,
    pub flags: Vec<String>,
    pub content: Option<MessageContent>,
    pub(crate) raw: Zeroizing<Vec<u8>>,
}

fn contains_line_break(value: &str) -> bool {
    value.contains('\r') || value.contains('\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_rejects_header_injection_and_missing_recipients() {
        let from = EmailAddress::new(None, "alice@example.com".into()).expect("valid sender");
        let draft = EmailDraft {
            from,
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: None,
            subject: "hello\r\nBcc: attacker@example.com".into(),
            text_body: None,
            html_body: None,
            attachments: Vec::new(),
            in_reply_to: None,
            references: Vec::new(),
            priority: MessagePriority::Normal,
        };
        assert!(draft.validate().is_err());
    }

    #[test]
    fn draft_debug_output_redacts_content() {
        let draft = EmailDraft {
            from: EmailAddress::new(None, "alice@example.com".into()).expect("sender"),
            to: vec![EmailAddress::new(None, "bob@example.com".into()).expect("recipient")],
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: None,
            subject: "private subject".into(),
            text_body: Some(Zeroizing::new("private body".into())),
            html_body: None,
            attachments: Vec::new(),
            in_reply_to: None,
            references: Vec::new(),
            priority: MessagePriority::Normal,
        };
        let debug = format!("{draft:?}");
        assert!(!debug.contains("private subject"));
        assert!(!debug.contains("private body"));
        assert!(!debug.contains("bob@example.com"));
    }
}
