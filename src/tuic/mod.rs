//! TUIC 协议层模块
//!
//! 设计原因：TUIC 协议的编解码逻辑与传输层无关，可独立复用。
//! 本模块实现 TUIC v5 协议的命令/地址/UDP分片编解码，
//! 参照 github.com/tuic-protocol/tuic SPEC.md 和 wind-tuic proto 源码。
//!
//! TUIC 协议极简：5 种命令（Auth/Connect/Packet/Dissociate/Heartbeat），
//! 每个命令帧以 2 字节包头 [VER=0x05][CMD] 开头，后续跟命令特定数据。
//! 帧边界由 QUIC stream/datagram 承载（协议本身不分帧）。

pub mod addr;
pub mod proto;
pub mod udp;

pub use addr::Address;
pub use proto::{Command, CmdType, VER};
