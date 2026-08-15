# RMail

RMail 是一个以安全、跨平台和简洁体验为目标的邮件客户端。项目当前遵循“先 CLI、后 GUI”的路线：先验证可复用的核心逻辑和存储边界，再接入 Tauri。

## 当前 CLI

```text
cargo run -- config add
cargo run -- config list
cargo run -- config show [配置ID]
cargo run -- config path
```

`config add` 会执行以下流程：

1. 读取并校验邮箱地址；
2. 从常见服务商预设中选择 IMAP/SMTP 参数，或按邮箱域名推断；
3. 让用户确认推断结果，也允许手动输入服务器、端口和 TLS 模式；
4. 隐藏回显地读取邮箱密码或应用专用密码；
5. 使用随机密钥和 XChaCha20-Poly1305 对完整账号配置进行认证加密；
6. 将随机密钥写入操作系统凭据库，将加密信封写入 TOML 文件。

部分邮件服务商不接受网页登录密码，可能要求应用专用密码。服务器推断不会代替实际网络连接验证；对于未知服务商，应在保存前核对其官方文档。

## 数据目录

默认使用操作系统标准的 RMail 本地数据目录。可以通过全局参数 `--data-dir <目录>` 覆盖根目录。根目录内按职责划分：

```text
RMail/
├── accounts/       # 加密账号配置（TOML 信封）
├── mail/           # 后续邮件数据模块
└── preferences/    # 后续偏好数据模块
```

账号文件名只包含随机配置 ID。TOML 信封仅包含格式版本、配置 ID、算法标识、随机 nonce 和密文；邮箱、密码及服务器地址均不以明文持久化。主密钥存放位置为：

- Windows：Credential Manager
- macOS：Keychain
- Linux：Secret Service

若系统安全凭据库不可用，RMail 会明确报错，不会降级为明文或把密钥写到配置目录。`config list` 和 `config show` 会在内存中解密配置，但绝不向终端显示密码。

## 质量检查

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```
