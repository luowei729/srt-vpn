//! tunnel/mod.rs — 隧道层（多路复用 + TS 伪装 + 会话管理）
//!
//! 设计决策（Q7/Q9/Q14）：
//! - 单 SRT 连接 + 多路复用层（256 会话，u16 会话 ID，帧头版本 v1）
//! - 单层可靠模型：可靠传输交给 SRT 层，复用层只做分帧+调度+窗口流控
//! - 所有帧（含 ACK）统一封装为 188B MPEG-TS 包（伪装一致性）
//! - -m 服务端配置 UDP 可靠/尽力而为，握手协商

pub mod dispatch;
pub mod multiplex;
pub mod session;

/// 复用层协议版本（v1）
pub const PROTOCOL_VERSION: u8 = 1;

/// 最大并发会话数（u16 会话 ID 上限 256，设计决策）
/// （P1 后半段接入会话路由时启用）
#[allow(dead_code)]
pub const MAX_SESSIONS: usize = 256;

/// 隧道协议 Magic（4 字节，区分 TS 流中的隧道帧）
pub const TUNNEL_MAGIC: [u8; 4] = *b"SRTV";

/// 帧类型（复用层帧头 Type 字段）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// 数据帧（承载应用数据）
    Data = 0x01,
    /// ACK（窗口推进/流控信号）
    Ack = 0x02,
    /// NACK（丢包报告，best-effort 模式用）
    Nack = 0x03,
    /// 挑战（服务器下发 nonce）
    Challenge = 0x10,
    /// 应答（客户端响应）
    Response = 0x11,
    /// 心跳（保活）
    Heartbeat = 0x12,
    /// 打开会话（建立新会话）
    Open = 0x20,
    /// 关闭会话（正常关闭）
    Close = 0x21,
    /// 单向关闭（TCP 半关闭 FIN 传播）
    Fin = 0x22,
    /// 会话重置（错误）
    Rst = 0x23,
}

impl FrameType {
    /// 从字节解析帧类型
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Data),
            0x02 => Some(Self::Ack),
            0x03 => Some(Self::Nack),
            0x10 => Some(Self::Challenge),
            0x11 => Some(Self::Response),
            0x12 => Some(Self::Heartbeat),
            0x20 => Some(Self::Open),
            0x21 => Some(Self::Close),
            0x22 => Some(Self::Fin),
            0x23 => Some(Self::Rst),
            _ => None,
        }
    }
}

/// 帧标志位
/// （FLAG_FIN/RST/WINDOW 在 P1 后半段接入半关闭/流控时启用）
#[allow(dead_code)]
pub const FLAG_FIN: u8 = 0x01;     // 单向关闭（半关闭传播）
#[allow(dead_code)]
pub const FLAG_RST: u8 = 0x02;     // 会话重置
pub const FLAG_RELIABLE: u8 = 0x04; // 可靠传输标记（协商后固定）
#[allow(dead_code)]
pub const FLAG_WINDOW: u8 = 0x08;  // 携带窗口更新

/// 复用层帧头布局（12 字节）：
/// [0..4)   Magic "SRTV"
/// [4]      Version (1)
/// [5]      Type (FrameType)
/// [6..8)   Session ID (u16 BE)
/// [8..10)  Payload 长度 (u16 BE)
/// [10..14) 序号 (u32 BE)
/// [14]     标志位 (1B)
/// 帧头共 15 字节，payload 最大 173 字节（188-15，TS 单包）
pub const FRAME_HEADER_LEN: usize = 15;

/// 会话方向（标识连接发起方）
/// （P1 后半段接入会话路由时启用）
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDir {
    /// 客户端发起（SOCKS5 入口连接）
    ClientInitiated,
    /// 服务端发起（转发出口回连）
    ServerInitiated,
}
