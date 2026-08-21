//! TUIC 地址编解码模块
//!
//! 设计原因：TUIC 的地址编码格式与 SOCKS5 类似但略有不同。
//! 支持三种地址类型：Domain / IPv4 / IPv6，用 1 字节 ATYP 区分。
//!
//! 线格式：
//! - Domain: [ATYP=0x00][len: u8][domain 字符串][port: u16 BE]
//! - IPv4:   [ATYP=0x01][4B IP][port: u16 BE]
//! - IPv6:   [ATYP=0x02][16B IP][port: u16 BE]
//! - None:   [ATYP=0xff]（用于 UDP 非首片分片，无地址信息）

use std::net::{Ipv4Addr, Ipv6Addr};
use bytes::{Buf, BufMut};

/// 地址类型标识符
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// 域名地址（ATYP=0x00）
    Domain = 0x00,
    /// IPv4 地址（ATYP=0x01）
    IPv4 = 0x01,
    /// IPv6 地址（ATYP=0x02）
    IPv6 = 0x02,
    /// 无地址（ATYP=0xff，用于 UDP 非首片分片）
    None = 0xff,
}

impl AddressType {
    /// 从 u8 转换为 AddressType
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Domain),
            0x01 => Some(Self::IPv4),
            0x02 => Some(Self::IPv6),
            0xff => Some(Self::None),
            _ => None,
        }
    }
}

/// TUIC 地址枚举
///
/// 用于 Connect 命令的目标地址和 Packet 命令的首片地址。
/// 非首片 UDP 分片用 Address::None。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// 无地址（UDP 非首片分片用）
    None,
    /// 域名 + 端口
    Domain(String, u16),
    /// IPv4 + 端口
    IPv4(Ipv4Addr, u16),
    /// IPv6 + 端口
    IPv6(Ipv6Addr, u16),
}

impl Address {
    /// 创建域名地址
    pub fn domain(host: impl Into<String>, port: u16) -> Self {
        Self::Domain(host.into(), port)
    }

    /// 创建 IPv4 地址
    pub fn ipv4(ip: Ipv4Addr, port: u16) -> Self {
        Self::IPv4(ip, port)
    }

    /// 创建 IPv6 地址
    pub fn ipv6(ip: Ipv6Addr, port: u16) -> Self {
        Self::IPv6(ip, port)
    }

    /// 从 std::net::SocketAddr 创建（自动区分 v4/v6）
    pub fn from_socket_addr(addr: std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(v4) => Self::IPv4(*v4.ip(), v4.port()),
            std::net::SocketAddr::V6(v6) => Self::IPv6(*v6.ip(), v6.port()),
        }
    }

    /// 解析为 std::net::SocketAddr（仅 IP 地址类型，域名需先 DNS 解析）
    ///
    /// 返回 None 表示域名类型，需要外部解析
    pub fn to_socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::IPv4(ip, port) => Some(std::net::SocketAddr::new((*ip).into(), *port)),
            Self::IPv6(ip, port) => Some(std::net::SocketAddr::new((*ip).into(), *port)),
            Self::None | Self::Domain(_, _) => None,
        }
    }

    /// 获取端口号
    pub fn port(&self) -> Option<u16> {
        match self {
            Self::None => None,
            Self::Domain(_, p) | Self::IPv4(_, p) | Self::IPv6(_, p) => Some(*p),
        }
    }

    /// 获取主机字符串（域名或 IP 字符串）
    pub fn host(&self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Domain(h, _) => Some(h.clone()),
            Self::IPv4(ip, _) => Some(ip.to_string()),
            Self::IPv6(ip, _) => Some(ip.to_string()),
        }
    }

    /// 编码到 bytes::BufMut
    ///
    /// 将地址写入缓冲区，返回写入的字节数
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::None => {
                // 无地址：仅写入 ATYP=0xff
                buf.put_u8(AddressType::None as u8);
            }
            Self::Domain(host, port) => {
                // 域名：ATYP(1) + len(1) + domain + port(2)
                buf.put_u8(AddressType::Domain as u8);
                // 域名长度（1 字节，最大 255）
                debug_assert!(host.len() <= 255, "域名长度超过 255 字节");
                buf.put_u8(host.len() as u8);
                buf.put_slice(host.as_bytes());
                buf.put_u16(*port); // 端口大端编码
            }
            Self::IPv4(ip, port) => {
                // IPv4：ATYP(1) + 4B IP + port(2)
                buf.put_u8(AddressType::IPv4 as u8);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
            }
            Self::IPv6(ip, port) => {
                // IPv6：ATYP(1) + 16B IP + port(2)
                buf.put_u8(AddressType::IPv6 as u8);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
            }
        }
    }

    /// 编码为 Vec<u8>（便捷方法）
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 255 + 2); // 最大: ATYP + 域名 + port
        self.encode(&mut buf);
        buf
    }

    /// 从字节切片解码地址（便捷方法，返回地址和消耗的字节数）
    ///
    /// 内部用 bytes::Buf 实现，同时返回消费了多少字节
    pub fn decode_from_slice(data: &[u8]) -> Result<(Self, usize), AddrError> {
        use bytes::Buf;
        let total = data.len();
        let mut buf = &data[..]; // &[u8] 实现 Buf
        let addr = Self::decode(&mut buf)?;
        let consumed = total - buf.remaining(); // 总长度减去剩余就是消费的字节数
        Ok((addr, consumed))
    }

    /// 从 bytes::Buf 解码地址
    ///
    /// 返回解码后的 Address 和消耗的字节数
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, AddrError> {
        if buf.remaining() < 1 {
            return Err(AddrError::Incomplete);
        }

        // 读取地址类型标识符
        let atyp = buf.get_u8();
        let addr_type = AddressType::from_u8(atyp)
            .ok_or(AddrError::InvalidAddressType(atyp))?;

        match addr_type {
            AddressType::None => {
                // 无地址：仅 ATYP=0xff
                Ok(Self::None)
            }
            AddressType::Domain => {
                // 域名：len(1) + domain + port(2)
                if buf.remaining() < 1 {
                    return Err(AddrError::Incomplete);
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    return Err(AddrError::Incomplete);
                }
                let domain = String::from_utf8(buf.copy_to_bytes(len).to_vec())
                    .map_err(|_| AddrError::InvalidDomain)?;
                let port = buf.get_u16();
                Ok(Self::Domain(domain, port))
            }
            AddressType::IPv4 => {
                // IPv4：4B IP + port(2)
                if buf.remaining() < 4 + 2 {
                    return Err(AddrError::Incomplete);
                }
                let octets = buf.copy_to_bytes(4);
                let ip = Ipv4Addr::from(octents_to_array_4(&octets));
                let port = buf.get_u16();
                Ok(Self::IPv4(ip, port))
            }
            AddressType::IPv6 => {
                // IPv6：16B IP + port(2)
                if buf.remaining() < 16 + 2 {
                    return Err(AddrError::Incomplete);
                }
                let octets = buf.copy_to_bytes(16);
                let ip = Ipv6Addr::from(octents_to_array_16(&octets));
                let port = buf.get_u16();
                Ok(Self::IPv6(ip, port))
            }
        }
    }
}

/// 将 bytes::Bytes 转为 4 字节数组（IPv4）
fn octents_to_array_4(b: &[u8]) -> [u8; 4] {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&b[..4]);
    arr
}

/// 将 bytes::Bytes 转为 16 字节数组（IPv6）
fn octents_to_array_16(b: &[u8]) -> [u8; 16] {
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&b[..16]);
    arr
}

/// 地址解码错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrError {
    /// 数据不完整（缓冲区不足）
    Incomplete,
    /// 无效的地址类型
    InvalidAddressType(u8),
    /// 无效的域名（非 UTF-8）
    InvalidDomain,
}

impl std::fmt::Display for AddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddrError::Incomplete => write!(f, "地址数据不完整"),
            AddrError::InvalidAddressType(t) => write!(f, "无效地址类型: 0x{:02x}", t),
            AddrError::InvalidDomain => write!(f, "无效域名（非UTF-8）"),
        }
    }
}

impl std::error::Error for AddrError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tuic::proto::VER;

    #[test]
    fn test_encode_decode_domain() {
        let addr = Address::domain("example.com", 443);
        let encoded = addr.encode_to_vec();
        // ATYP(0x00) + len(11) + "example.com" + port(443=0x01BB)
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 11);
        assert_eq!(&encoded[2..13], b"example.com");
        assert_eq!(&encoded[13..15], &[0x01, 0xBB]);

        // 解码回来
        let mut buf = &encoded[..];
        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_encode_decode_ipv4() {
        let addr = Address::ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        let encoded = addr.encode_to_vec();
        // ATYP(0x01) + 4B IP + port(8080=0x1F90)
        assert_eq!(encoded[0], 0x01);
        assert_eq!(&encoded[1..5], &[127, 0, 0, 1]);

        let mut buf = &encoded[..];
        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_encode_decode_ipv6() {
        let addr = Address::ipv6(Ipv6Addr::LOCALHOST, 443);
        let encoded = addr.encode_to_vec();
        assert_eq!(encoded[0], 0x02);

        let mut buf = &encoded[..];
        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_encode_decode_none() {
        let addr = Address::None;
        let encoded = addr.encode_to_vec();
        assert_eq!(encoded, vec![0xff]);

        let mut buf = &encoded[..];
        let decoded = Address::decode(&mut buf).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_wire_format_connect_ipv4() {
        // 验证 TUIC Connect 命令的线格式：
        // VER(5) CMD(1) ATYP(1) 127.0.0.1 port=80
        let addr = Address::ipv4(Ipv4Addr::new(127, 0, 0, 1), 80);
        let mut buf = Vec::new();
        buf.put_u8(VER); // VER=5
        buf.put_u8(1); // CMD=Connect
        addr.encode(&mut buf);
        assert_eq!(&buf[..], &[VER, 1, 1, 127, 0, 0, 1, 0, 80]);
    }

    #[test]
    fn test_wire_format_domain() {
        // 验证域名地址线格式：
        // ATYP(0) LEN(5) "ab.cd" port=443(0x01BB)
        let addr = Address::domain("ab.cd", 443);
        let encoded = addr.encode_to_vec();
        assert_eq!(&encoded[..], &[0, 5, b'a', b'b', b'.', b'c', b'd', 0x01, 0xBB]);
    }
}
