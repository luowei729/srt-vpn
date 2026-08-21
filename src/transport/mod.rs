//! 传输层模块
//!
//! 设计原因：传输层是整个项目的核心，负责：
//! 1. 用 quinn-proto（成熟 QUIC 状态机，无 I/O）处理 QUIC 协议逻辑
//! 2. 自管 UdpSocket 收发，在 I/O 层做包级 AES-128-CTR 加密
//! 3. 加密后的 QUIC 包套 SRT 0x80 外壳发送（DPI 看不到 QUIC/TLS 明文）
//! 4. tokio select! 桥接 socket 就绪 + 定时器 + 应用事件
//!
//! 分层：
//! - srt_shell.rs：SRT 0x80 外壳编解码（握手/数据头/ACK 节奏仿真）
//! - crypto.rs：双阶段 AES-128-CTR 包级加密
//! - driver.rs：quinn-proto Endpoint/Connection 驱动循环（tokio 桥接）

pub mod crypto;
pub mod driver;
pub mod srt_shell;
