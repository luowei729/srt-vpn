//! TUIC 命令编解码模块
//!
//! 设计原因：TUIC v5 协议定义了 5 种命令，每种命令有特定的字段和线格式。
//! 命令帧以 2 字节包头 [VER=0x05][CMD] 开头，后续跟命令特定数据。
//!
//! 命令类型与线格式：
//! - Auth(0x00):       [VER][0x00][uuid 16B][token 32B]            共 50B
//! - Connect(0x01):   [VER][0x01][Address]                         走 QUIC bi-stream
//! - Packet(0x02):    [VER][0x02][assoc_id 2B][pkt_id 2B]
//!                     [frag_total 1B][frag_id 1B][size 2B]
//!                     [Address][payload]
//! - Dissociate(0x03): [VER][0x03][assoc_id 2B]                   共 4B
//! - Heartbeat(0x04):  [VER][0x04]                                共 2B

use crate::tuic::addr::Address;
use bytes::{Buf, BufMut};
use uuid::Uuid;

/// TUIC 协议版本号
pub const VER: u8 = 0x05;

/// 命令类型枚举（对应包头第 2 字节 CMD）
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdType {
    /// 认证命令（在 QUIC uni-stream 上发送，携带 UUID + TLS exporter token）
    Auth = 0x00,
    /// TCP 连接命令（在 QUIC bi-stream 上发送，携带目标地址）
    Connect = 0x01,
    /// UDP 数据包命令（携带分片信息和目标地址）
    Packet = 0x02,
    /// 断开 UDP 关联命令
    Dissociate = 0x03,
    /// 心跳命令
    Heartbeat = 0x04,
}

impl CmdType {
    /// 从 u8 转换为 CmdType
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Auth),
            0x01 => Some(Self::Connect),
            0x02 => Some(Self::Packet),
            0x03 => Some(Self::Dissociate),
            0x04 => Some(Self::Heartbeat),
            _ => None,
        }
    }
}

/// TUIC 命令枚举
///
/// 每个变体对应一种 TUIC 命令，包含该命令的完整数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// 认证命令：UUID + TLS exporter 派生的 32 字节 token
    ///
    /// 客户端在 QUIC 握手后通过 uni-stream 发送给服务端。
    /// 服务端用相同的 UUID+password 派生 token 比对验证。
    Auth {
        /// 客户端 UUID（16 字节，明文传输）
        uuid: Uuid,
        /// TLS exporter 派生的认证 token（32 字节）
        token: [u8; 32],
    },

    /// TCP 连接命令：在 QUIC 双向流上发送，携带目标地址
    ///
    /// 客户端打开 bi-stream → 发送 Connect 命令 → 开始流式传输数据。
    /// 服务端收到后建立 TCP 连接到目标地址，双向桥接。
    Connect {
        /// 目标地址
        addr: Address,
    },

    /// UDP 数据包命令：携带分片信息和目标地址
    ///
    /// 用于 UDP 代理。大包可分片（frag_total > 1），非首片 Address=None。
    Packet {
        /// UDP 关联 ID（会话标识）
        assoc_id: u16,
        /// 数据包 ID（同一关联内的递增序号，用于分片重组）
        pkt_id: u16,
        /// 分片总数（1=无分片）
        frag_total: u8,
        /// 当前分片序号（0-based）
        frag_id: u8,
        /// payload 大小（字节）
        size: u16,
        /// 目标地址（非首片为 None）
        addr: Address,
        /// 数据载荷
        payload: Vec<u8>,
    },

    /// 断开 UDP 关联命令
    ///
    /// 客户端发送此命令终止一个 UDP 会话。
    Dissociate {
        /// 要断开的关联 ID
        assoc_id: u16,
    },

    /// 心跳命令（无数据）
    ///
    /// 用于保活检测，客户端定期发送。
    Heartbeat,
}

impl Command {
    /// 获取命令类型
    pub fn cmd_type(&self) -> CmdType {
        match self {
            Self::Auth { .. } => CmdType::Auth,
            Self::Connect { .. } => CmdType::Connect,
            Self::Packet { .. } => CmdType::Packet,
            Self::Dissociate { .. } => CmdType::Dissociate,
            Self::Heartbeat => CmdType::Heartbeat,
        }
    }

    /// 编码命令到 bytes::BufMut
    ///
    /// 将完整的命令（含 2 字节包头）写入缓冲区。
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        // 写入包头：VER + CMD
        buf.put_u8(VER);
        buf.put_u8(self.cmd_type() as u8);

        match self {
            Self::Auth { uuid, token } => {
                // Auth: uuid(16B) + token(32B)
                buf.put_slice(uuid.as_bytes()); // UUID 16 字节
                buf.put_slice(token); // token 32 字节
            }

            Self::Connect { addr } => {
                // Connect: Address（目标地址）
                addr.encode(buf);
            }

            Self::Packet {
                assoc_id,
                pkt_id,
                frag_total,
                frag_id,
                size,
                addr,
                payload,
            } => {
                // Packet: assoc_id(2) + pkt_id(2) + frag_total(1) + frag_id(1)
                //         + size(2) + Address + payload
                buf.put_u16(*assoc_id);
                buf.put_u16(*pkt_id);
                buf.put_u8(*frag_total);
                buf.put_u8(*frag_id);
                buf.put_u16(*size);
                addr.encode(buf);
                buf.put_slice(payload);
            }

            Self::Dissociate { assoc_id } => {
                // Dissociate: assoc_id(2)
                buf.put_u16(*assoc_id);
            }

            Self::Heartbeat => {
                // Heartbeat: 无额外数据
            }
        }
    }

    /// 编码为 Vec<u8>（便捷方法）
    pub fn encode_to_vec(&self) -> Vec<u8> {
        // 预估容量（最大情况：Packet 命令带大 payload）
        let capacity = match self {
            Self::Auth { .. } => 2 + 16 + 32,       // 50
            Self::Connect { addr } => 2 + addr.encode_to_vec().len(),
            Self::Packet { payload, .. } => 2 + 8 + 255 + 2 + payload.len(),
            Self::Dissociate { .. } => 2 + 2,       // 4
            Self::Heartbeat => 2,
        };
        let mut buf = Vec::with_capacity(capacity);
        self.encode(&mut buf);
        buf
    }

    /// 从字节切片解码命令
    ///
    /// 读取完整的命令（含 2 字节包头），返回命令和消耗的字节数。
    pub fn decode(data: &[u8]) -> Result<(Self, usize), CmdError> {
        if data.len() < 2 {
            return Err(CmdError::Incomplete);
        }

        // 读取包头
        let ver = data[0];
        if ver != VER {
            return Err(CmdError::InvalidVersion(ver));
        }

        let cmd_byte = data[1];
        let cmd_type = CmdType::from_u8(cmd_byte)
            .ok_or(CmdError::InvalidCommand(cmd_byte))?;

        let mut offset = 2; // 跳过包头

        let cmd = match cmd_type {
            CmdType::Auth => {
                // Auth: uuid(16B) + token(32B) = 48 字节
                if data.len() < offset + 48 {
                    return Err(CmdError::Incomplete);
                }
                let uuid_bytes = &data[offset..offset + 16];
                let uuid = Uuid::from_slice(uuid_bytes)
                    .map_err(|_| CmdError::InvalidUuid)?;
                offset += 16;

                let mut token = [0u8; 32];
                token.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;

                Self::Auth { uuid, token }
            }

            CmdType::Connect => {
                // Connect: Address
                let (addr, consumed) = Address::decode_from_slice(&data[offset..])?;
                offset += consumed;
                Self::Connect { addr }
            }

            CmdType::Packet => {
                // Packet: assoc_id(2) + pkt_id(2) + frag_total(1) + frag_id(1)
                //         + size(2) + Address + payload
                if data.len() < offset + 8 {
                    return Err(CmdError::Incomplete);
                }
                let assoc_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                let pkt_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                let frag_total = data[offset];
                offset += 1;
                let frag_id = data[offset];
                offset += 1;
                let size = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;

                let (addr, addr_consumed) = Address::decode_from_slice(&data[offset..])?;
                offset += addr_consumed;

                // 读取 payload
                let payload_len = size as usize;
                if data.len() < offset + payload_len {
                    return Err(CmdError::Incomplete);
                }
                let payload = data[offset..offset + payload_len].to_vec();
                offset += payload_len;

                Self::Packet {
                    assoc_id,
                    pkt_id,
                    frag_total,
                    frag_id,
                    size,
                    addr,
                    payload,
                }
            }

            CmdType::Dissociate => {
                // Dissociate: assoc_id(2)
                if data.len() < offset + 2 {
                    return Err(CmdError::Incomplete);
                }
                let assoc_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                Self::Dissociate { assoc_id }
            }

            CmdType::Heartbeat => {
                // Heartbeat: 无额外数据
                Self::Heartbeat
            }
        };

        Ok((cmd, offset))
    }
}

/// 命令解码错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmdError {
    /// 数据不完整
    Incomplete,
    /// 无效的协议版本号
    InvalidVersion(u8),
    /// 无效的命令类型
    InvalidCommand(u8),
    /// 无效的 UUID
    InvalidUuid,
    /// 地址解码错误
    AddrError(crate::tuic::addr::AddrError),
}

impl std::fmt::Display for CmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CmdError::Incomplete => write!(f, "命令数据不完整"),
            CmdError::InvalidVersion(v) => write!(f, "无效协议版本: 0x{:02x}（期望 0x05）", v),
            CmdError::InvalidCommand(c) => write!(f, "无效命令类型: 0x{:02x}", c),
            CmdError::InvalidUuid => write!(f, "无效 UUID"),
            CmdError::AddrError(e) => write!(f, "地址解码错误: {}", e),
        }
    }
}

impl std::error::Error for CmdError {}

impl From<crate::tuic::addr::AddrError> for CmdError {
    fn from(e: crate::tuic::addr::AddrError) -> Self {
        Self::AddrError(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tuic::addr::Address;
    use std::net::Ipv4Addr;

    #[test]
    fn test_encode_decode_auth() {
        let uuid = Uuid::nil(); // 全零 UUID 用于测试
        let token = [1u8; 32]; // 全 1 token 用于测试
        let cmd = Command::Auth { uuid, token };

        let encoded = cmd.encode_to_vec();
        // VER(5) + CMD(0) + uuid(16×0) + token(32×1)
        assert_eq!(encoded.len(), 50);
        assert_eq!(encoded[0], VER);
        assert_eq!(encoded[1], 0x00);

        let (decoded, consumed) = Command::decode(&encoded).unwrap();
        assert_eq!(consumed, 50);
        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_encode_decode_connect_ipv4() {
        let cmd = Command::Connect {
            addr: Address::ipv4(Ipv4Addr::new(127, 0, 0, 1), 80),
        };

        let encoded = cmd.encode_to_vec();
        // VER(5) + CMD(1) + ATYP(1) + IP(4) + port(2) = 9
        assert_eq!(encoded.len(), 9);
        assert_eq!(&encoded[..], &[VER, 1, 1, 127, 0, 0, 1, 0, 80]);

        let (decoded, consumed) = Command::decode(&encoded).unwrap();
        assert_eq!(consumed, 9);
        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_encode_decode_connect_domain() {
        let cmd = Command::Connect {
            addr: Address::domain("example.com", 443),
        };

        let encoded = cmd.encode_to_vec();
        let (decoded, consumed) = Command::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_encode_decode_packet() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let cmd = Command::Packet {
            assoc_id: 42,
            pkt_id: 100,
            frag_total: 1,
            frag_id: 0,
            size: payload.len() as u16,
            addr: Address::ipv4(Ipv4Addr::new(8, 8, 8, 8), 53),
            payload: payload.clone(),
        };

        let encoded = cmd.encode_to_vec();
        let (decoded, consumed) = Command::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_encode_decode_dissociate() {
        let cmd = Command::Dissociate { assoc_id: 42 };

        let encoded = cmd.encode_to_vec();
        assert_eq!(encoded.len(), 4);
        assert_eq!(&encoded[..], &[VER, 3, 0, 42]);

        let (decoded, consumed) = Command::decode(&encoded).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_encode_decode_heartbeat() {
        let cmd = Command::Heartbeat;

        let encoded = cmd.encode_to_vec();
        assert_eq!(encoded.len(), 2);
        assert_eq!(&encoded[..], &[VER, 4]);

        let (decoded, consumed) = Command::decode(&encoded).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_invalid_version() {
        let data = [0x04, 0x00]; // 错误版本号
        let result = Command::decode(&data);
        assert!(matches!(result, Err(CmdError::InvalidVersion(4))));
    }

    #[test]
    fn test_invalid_command() {
        let data = [VER, 0x99]; // 无效命令类型
        let result = Command::decode(&data);
        assert!(matches!(result, Err(CmdError::InvalidCommand(0x99))));
    }
}
