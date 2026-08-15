pub mod mime;
pub mod model;

pub use model::{
    Attachment, AttachmentDisposition, Authentication, EmailAddress, EmailDraft, MessageContent,
    MessageEnvelope, MessagePriority, MessageSource, ReceivedAttachment, ReceivedMessage,
};
