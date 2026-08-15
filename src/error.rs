use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, RMailError>;

#[derive(Debug, Error)]
pub enum RMailError {
    #[error("邮箱地址无效：{0}")]
    InvalidEmail(&'static str),

    #[error("邮件服务器配置无效：{0}")]
    InvalidServer(&'static str),

    #[error("密码不能为空")]
    EmptyPassword,

    #[error("选项无效：{0}")]
    InvalidChoice(&'static str),

    #[error("邮件内容无效：{0}")]
    InvalidMessage(&'static str),

    #[error("邮件协议操作失败：{0}")]
    Protocol(&'static str),

    #[error("无法确定系统数据目录，请使用 --data-dir 指定目录")]
    DataDirectoryUnavailable,

    #[error("配置 ID 无效")]
    InvalidProfileId,

    #[error("找不到配置 {0}")]
    ProfileNotFound(String),

    #[error("存在多个账号，请明确指定配置 ID")]
    AmbiguousProfile,

    #[error("尚未保存任何账号")]
    NoProfiles,

    #[error("加密配置格式无效：{0}")]
    InvalidEnvelope(&'static str),

    #[error("配置认证或解密失败；文件、密钥或配置 ID 可能不匹配")]
    DecryptionFailed,

    #[error("系统凭据库操作失败：{0}")]
    KeyStore(String),

    #[error("读取输入失败：{0}")]
    Input(#[source] std::io::Error),

    #[error("{action}失败（{path}）：{source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("序列化配置失败：{0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("解析配置失败：{0}")]
    Deserialize(#[from] toml::de::Error),
}
