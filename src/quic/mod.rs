//! quic/mod.rs — 自研 QUIC 语义传输内核
//!
//! 2026-08-20 重构共识（PROJECT_PLAN 第五节）：
//! 废弃 libsrt，用 Rust 自研"借鉴 RFC 9000 传输机制"的轻量内核。
//! 与标准 QUIC 的差异（关键判断）：
//! - **无 TLS 1.3 Initial 明文**：首包按 SRT 0x80 外壳写，内层帧走认证握手（srt_shell）
//! - 不依赖 quiche/msquic（它们绑死 TLS 指纹，无法伪装 SRT）
//! - 单连接共享拥塞控制窗口（决策 F：学 QUIC 流控即跑满带宽）
//!
//! 分层（自底向上）：
//! - packet.rs：varint + 帧编解码（STREAM/ACK/PING/PONG/RST_STREAM/MAX_DATA/握手）
//! - stream.rs：多流接口（256 流上限，流级缓冲/乱序重组/FIN 语义）
//! - ack.rs：ACK/丢失恢复（包序号跟踪 + 重传队列）
//! - congctl.rs：拥塞控制（BBR 起步，窗口=带宽×RTT 估计）
//! - connection.rs：连接状态机（握手/运行/关闭，收发包调度）
//! - crypto.rs：载荷加密（SRT 特征密钥派生，替代 libsrt 加密）

pub mod ack;
pub mod congctl;
pub mod connection;
pub mod crypto;
pub mod listener;
pub mod packet;
pub mod stream;