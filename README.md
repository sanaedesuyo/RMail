# RMail

RMail 是一个以安全、跨平台和简洁体验为目标的邮件客户端。项目当前遵循“先 CLI、后 GUI”的路线：先验证可复用的核心逻辑和存储边界，再接入 Tauri。

## 当前 CLI

```text
cargo run -- config add
cargo run -- config update <配置ID>
cargo run -- config delete <配置ID>
cargo run -- config log-limit <数量>
cargo run -- config list
cargo run -- config show [配置ID]
cargo run -- config path
cargo run -- send --account <配置ID> --to <收件人> --subject <主题> --text-file <正文文件>
cargo run -- receive --account <配置ID> --protocol imap
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

`config update <配置ID>` 以交互式方式更新邮箱地址、密码或 IMAP/SMTP 服务器，未填写的字段保持原值，并使用原系统密钥重新加密配置。`config delete <配置ID>` 会要求再次输入完整配置 ID；确认后删除加密账号文件及其操作系统凭据库密钥。

## 日志

日志写入数据目录的 `logs/rmail.log`，仅包含时间戳、等级和受限的内部事件代码；不会记录账号、服务器、邮件内容、路径、凭据或令牌。默认保留最新 1000 条，达到上限时淘汰最旧条目。通过 `config log-limit <1-100000>` 调整上限；该偏好保存在经系统凭据库密钥加密的 `preferences/logging.toml` 中。

## SMTP 发送与 IMAP/POP3 接收

发送使用账号配置中的 SMTP Submission 服务器。`--smtp-server`、`--smtp-port` 和 `--smtp-security` 可在单次操作中覆盖该设置；它们用于指定**中继服务器**，收件服务器由收件人地址的域名和 SMTP 路由决定。支持 TLS 或 STARTTLS，绝不会回退到明文认证或跳过证书校验。

```text
cargo run -- send --account <配置ID> --to bob@example.com --cc team@example.com \
  --subject "进度" --text-file body.txt --attachment report.pdf

cargo run -- receive --account <配置ID> --protocol imap --mailbox INBOX --limit 20
cargo run -- receive --account <配置ID> --protocol pop3 --server pop.example.com --security tls --full
```

`send` 支持 To、Cc、Bcc、Reply-To、线程 ID、纯文本/HTML 正文和每个最多 25 MiB 的附件。正文仅接受文件输入，避免把邮件内容放进 shell 历史。接收默认只获取邮件头；`--full` 才会读取正文与附件。POP3 从不发出服务器端删除邮件的命令。

## 本地邮件管理

接收的邮件会加密保存到对应账户的实际邮件箱；IMAP 同时从服务器拉取邮箱目录，POP3 仅创建 `INBOX`。`新邮件`、`已发送`、`回收站`与`星标邮件`是跨账户逻辑引用视图，不复制或明文保存邮件数据。

```text
cargo run -- mail list --local new
cargo run -- mail list --account <配置ID> --mailbox INBOX
cargo run -- mail delete --account <配置ID> <邮件ID>
cargo run -- mail restore --account <配置ID> <邮件ID>
cargo run -- mail purge --account <配置ID> <邮件ID> --confirm <邮件ID>
```

发送成功的邮件会写入账户实际 `Sent` 邮件箱，并出现在本地“已发送”视图。删除只移动本地加密邮件至回收站；接收、发送或任何邮件管理操作时，已在回收站超过 30 天的邮件会自动永久删除。`mail purge` 可在 30 天前手动永久删除，且必须再次提供相同邮件 ID。

## 质量检查

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```
