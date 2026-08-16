use std::str::FromStr;

use lettre::address::Address;
use lettre::message::header::ContentType;
use lettre::message::{Attachment as LettreAttachment, Mailbox, Message, MultiPart, SinglePart};
use mail_parser::{Address as ParsedAddress, MessageParser, MimeHeaders};
use zeroize::Zeroizing;

use crate::mail::model::{
    AttachmentDisposition, EmailAddress, EmailDraft, MessageContent, MessageEnvelope,
    ReceivedAttachment, ReceivedMessage,
};
use crate::{RMailError, Result};

pub fn build_message(draft: &EmailDraft) -> Result<Message> {
    draft.validate()?;
    let mut builder = Message::builder()
        .from(to_mailbox(&draft.from)?)
        .subject(&draft.subject);
    for recipient in &draft.to {
        builder = builder.to(to_mailbox(recipient)?);
    }
    for recipient in &draft.cc {
        builder = builder.cc(to_mailbox(recipient)?);
    }
    for recipient in &draft.bcc {
        builder = builder.bcc(to_mailbox(recipient)?);
    }
    if let Some(reply_to) = &draft.reply_to {
        builder = builder.reply_to(to_mailbox(reply_to)?);
    }
    if let Some(in_reply_to) = &draft.in_reply_to {
        builder = builder.in_reply_to(in_reply_to.clone());
    }
    if !draft.references.is_empty() {
        builder = builder.references(draft.references.join(" "));
    }

    let plain = draft
        .text_body
        .as_ref()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_default();
    let body = match &draft.html_body {
        Some(html) => MultiPart::alternative_plain_html(plain, html.to_string()),
        None => MultiPart::mixed().singlepart(SinglePart::plain(plain)),
    };
    let mut multipart = if draft.attachments.is_empty() {
        body
    } else {
        MultiPart::mixed().multipart(body)
    };
    for attachment in &draft.attachments {
        let content_type = ContentType::parse(&attachment.media_type)
            .map_err(|_| RMailError::InvalidMessage("附件 MIME 类型无效"))?;
        let part = match attachment.disposition {
            AttachmentDisposition::Attachment => LettreAttachment::new(attachment.filename.clone())
                .body(attachment.content.to_vec(), content_type),
            AttachmentDisposition::Inline => LettreAttachment::new_inline_with_name(
                attachment
                    .content_id
                    .clone()
                    .ok_or(RMailError::InvalidMessage("内联附件缺少 Content-ID"))?,
                attachment.filename.clone(),
            )
            .body(attachment.content.to_vec(), content_type),
        };
        multipart = multipart.singlepart(part);
    }
    builder
        .multipart(multipart)
        .map_err(|_| RMailError::InvalidMessage("无法构建 MIME 邮件"))
}

pub fn parse_message(
    source: crate::mail::model::MessageSource,
    raw: &[u8],
    include_content: bool,
) -> Result<ReceivedMessage> {
    let parsed = MessageParser::default()
        .with_mime_headers()
        .with_address_headers()
        .with_date_headers()
        .with_message_ids()
        .parse(raw)
        .ok_or(RMailError::Protocol("无法解析 RFC 5322/MIME 邮件"))?;
    let envelope = MessageEnvelope {
        message_id: parsed.message_id().map(ToOwned::to_owned),
        in_reply_to: parsed
            .header_raw("In-Reply-To")
            .map(split_message_ids)
            .unwrap_or_default(),
        references: parsed
            .header_raw("References")
            .map(split_message_ids)
            .unwrap_or_default(),
        subject: parsed.subject().map(ToOwned::to_owned),
        date_rfc3339: parsed.date().map(|date| date.to_rfc3339()),
        from: convert_addresses(parsed.from()),
        to: convert_addresses(parsed.to()),
        cc: convert_addresses(parsed.cc()),
        reply_to: convert_addresses(parsed.reply_to()),
    };
    let content = include_content.then(|| MessageContent {
        text: parsed
            .text_bodies()
            .filter_map(|part| part.text_contents())
            .map(|text| Zeroizing::new(text.to_owned()))
            .collect(),
        html: parsed
            .html_bodies()
            .filter_map(|part| part.text_contents())
            .map(|html| Zeroizing::new(html.to_owned()))
            .collect(),
        attachments: parsed
            .attachments()
            .map(|part| ReceivedAttachment {
                filename: part.attachment_name().map(ToOwned::to_owned),
                media_type: part.content_type().map(|content_type| {
                    content_type
                        .c_subtype
                        .as_ref()
                        .map(|subtype| format!("{}/{}", content_type.c_type, subtype))
                        .unwrap_or_else(|| content_type.c_type.to_string())
                }),
                content_id: part.content_id().map(ToOwned::to_owned),
                size: part.len(),
                content: Some(Zeroizing::new(part.contents().to_vec())),
            })
            .collect(),
    });
    Ok(ReceivedMessage {
        source,
        envelope,
        size: Some(raw.len().try_into().unwrap_or(u32::MAX)),
        flags: Vec::new(),
        content,
        raw: Zeroizing::new(raw.to_vec()),
    })
}

fn to_mailbox(address: &EmailAddress) -> Result<Mailbox> {
    let parsed = Address::from_str(&address.address)
        .map_err(|_| RMailError::InvalidMessage("收件人地址无效"))?;
    Ok(Mailbox::new(address.display_name.clone(), parsed))
}

fn convert_addresses(address: Option<&ParsedAddress<'_>>) -> Vec<EmailAddress> {
    address
        .into_iter()
        .flat_map(|address| address.iter())
        .filter_map(|address| {
            let value = address.address()?;
            EmailAddress::new(address.name().map(ToOwned::to_owned), value.to_owned()).ok()
        })
        .collect()
}

fn split_message_ids(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|id| id.starts_with('<') && id.ends_with('>'))
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::model::{EmailDraft, MessagePriority, MessageSource};

    #[test]
    fn builds_and_parses_multipart_message() {
        let draft = EmailDraft {
            from: EmailAddress::new(Some("Alice".into()), "alice@example.com".into())
                .expect("sender"),
            to: vec![EmailAddress::new(None, "bob@example.com".into()).expect("recipient")],
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: None,
            subject: "Hello".into(),
            text_body: Some(Zeroizing::new("plain".into())),
            html_body: Some(Zeroizing::new("<p>html</p>".into())),
            attachments: Vec::new(),
            in_reply_to: Some("<previous@example.com>".into()),
            references: vec!["<root@example.com>".into()],
            priority: MessagePriority::Normal,
        };
        let message = build_message(&draft).expect("build MIME");
        let parsed = parse_message(
            MessageSource::Imap {
                uid: Some(4),
                sequence: 1,
            },
            &message.formatted(),
            true,
        )
        .expect("parse MIME");
        assert_eq!(parsed.envelope.subject.as_deref(), Some("Hello"));
        let content = parsed.content.expect("content");
        assert_eq!(content.text[0].as_str(), "plain");
        assert_eq!(content.html[0].as_str(), "<p>html</p>");
    }
}
