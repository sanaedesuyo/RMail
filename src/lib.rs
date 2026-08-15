#![allow(non_snake_case)] // Cargo 包名必须保持为用户指定的 `RMail`。

pub mod account;
pub mod cli;
pub mod crypto;
pub mod error;
pub mod key_store;
pub mod mail;
pub mod mail_service;
pub mod protocol;
pub mod server;
pub mod service;
pub mod storage;

pub use error::{RMailError, Result};
