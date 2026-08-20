//! srt_shell/mod.rs — 手写 SRT 全仿外壳（流量伪装层）
//!
//! 2026-08-20 重构共识（决策 C）：手写 SRT 壳，实现"流量特征伪装成 SRT 直播流"。
//! 替代 libsrt 的线协议外形，但传输可靠性/多流/拥控全部由内部自研 QUIC 语义内核
//! （quic/）承担——libsrt 已彻底废弃。
//!
//! 职责：
//! - outer.rs：SRT 16B 固定头（SEQ/消息号/时间戳/ID）+ 包封装
//! - header.rs：SRT 首包 0x80 握手结构（控制位/版本/ReqType）
//! - handshake.rs：SRT 特征握手（拟真 libsrt 行为，防主动探测）
//! - ack.rs：SRT ACK 节奏仿真（周期性 ACK 包，保持包长/时序纹理）
//! - auth.rs：SRT 特征认证（passphrase 密钥派生 + challenge/response，防主动探测）
//!
//! 与 libsrt 的关键对齐点（DPI 识别面）：
//! - 首包 4 字节 = 0x80 00 00 00（控制 + HANDSHAKE 类型）——见 header.rs
//! - 数据包/控制包靠 SEQNO bit0 区分（数据=0，控制=1）
//! - ACK 包 = 0x80 02 00 00（控制 + ACK 类型）——见 ack.rs
//! - 版本字段 = 4（UDT/HS_VERSION_UDT4）
//! - payload 上限 1316B（与真 SRT 满 MSS 包长分布一致）

pub mod ack;
pub mod auth;
pub mod handshake;
pub mod header;
pub mod outer;