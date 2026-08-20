//! quic/packet.rs — 自研 QUIC 语义传输内核：包与帧编解码
//!
//! 设计背景（2026-08-20 重构共识，见 PROJECT_PLAN 第五节）：
//! 废弃 libsrt，自研"借鉴 RFC 9000 传输机制"的轻量内核。本文件实现线协议
//! 最底层：variable-length integer（varint）与帧类型/帧编解码。
//!
//! 分层说明：
//! - 最外层：SRT 全仿外壳（srt_shell/，16B 固定头 + 0x80 握手）——流量伪装
//! - 本模块：外壳内的传输帧——可靠性/多流/流控（自研 QUIC 语义）
//!
//! 帧布局（借鉴 RFC 9000 帧风格，但全部大端字节序简化实现）：
//!   [帧类型 u8][负载（按类型解释）]
//!   STREAM 帧：   [类型 0x0a][流 ID varint][偏移 varint][长度 varint][数据]
//!   ACK 帧：      [类型 0x02][最大已确认序号 varint][延迟 varint]
//!   PING 帧：      [类型 0x01]
//!   PONG 帧:      [类型 0x03][回声数据]
//!   RST_STREAM:   [类型 0x0b][流 ID varint][错误码 varint]
//!   MAX_DATA:     [类型 0x10][连接级窗口 varint]
//!   MAX_STREAM:   [类型 0x11][流 ID varint][流级窗口 varint]
//!   握手帧：       [类型 0xf0][载荷]
//!   (扩展：FIN 由 STREAM 帧高位置 FIN=1 标记，见 FrameFlags)

use std::io;

/// 连接级最大 UDP 负载（承载帧数据上限）
/// 参考 SRT 默认 payload 1316B（UDP 1500 - IP 20 - UDP 8 - SRT 头 16）
/// 这里外壳头为 16B，故传输帧数据上限 1316B（与 SRT payload 对齐，
/// 保证外层伪装包长分布与真 SRT 一致）。
pub const MAX_UDP_PAYLOAD: usize = 1316;

/// 帧类型（传输层，非复用层会话帧）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// PING（保活/探测）
    Ping = 0x01,
    /// ACK（确认已收序号）
    Ack = 0x02,
    /// PONG（PING 回声，带时间戳测 RTT）
    Pong = 0x03,
    /// STREAM（应用数据，多流）—— 低位 0x04
    Stream = 0x04,
    /// RST_STREAM（流重置）
    RstStream = 0x0b,
    /// MAX_DATA（连接级流控窗口更新）
    MaxData = 0x10,
    /// MAX_STREAM_DATA（流级流控窗口更新）
    MaxStreamData = 0x11,
    /// 握手帧（认证/密钥协商，包装 SRT 特征握手）
    Handshake = 0xf0,
}

impl FrameType {
    /// 从字节解析帧类型
    pub fn from_byte(b: u8) -> Option<Self> {
        // 注意：STREAM 帧类型 0x04 的低位可带 FIN 标志（0x05 = Stream+Fin）
        match b {
            0x01 => Some(Self::Ping),
            0x02 => Some(Self::Ack),
            0x03 => Some(Self::Pong),
            0x04 | 0x05 => Some(Self::Stream), // 0x04=Stream，0x05=Stream+FIN
            0x0b => Some(Self::RstStream),
            0x10 => Some(Self::MaxData),
            0x11 => Some(Self::MaxStreamData),
            0xf0 => Some(Self::Handshake),
            _ => None,
        }
    }
}

/// STREAM 帧标志（低 2 位内嵌在帧类型字节的低位）
pub const STREAM_FIN: u8 = 0x01; // 帧类型 0x05 = Stream + FIN

/// varint 编码（QUIC variable-length integer）
///
/// 格式（RFC 9000 §16）：
/// - 首字节高 2 位表示长度：00=1字节(6bit) 01=2字节(14bit) 10=4字节(30bit) 11=8字节(62bit)
/// - 剩余位为大端数值
///
/// 这里为了简化实现且保持线协议简洁，采用固定 1 字节长度编码（值 < 2^62，
/// 实际流 ID / 序号 / 长度都用 u32，1 字节足够绝大多数场景）。
/// 但为了可扩展性，实现完整的变长编码。
pub fn encode_varint(value: u64, out: &mut Vec<u8>) {
    // 按数值大小选择最小长度（QUIC 标准变长编码）
    if value < (1 << 6) {
        out.push(value as u8); // 00 + 6bit
    } else if value < (1 << 14) {
        out.push(0x40 | ((value >> 8) as u8)); // 01 + 14bit
        out.push((value & 0xFF) as u8);
    } else if value < (1 << 30) {
        out.push(0x80 | ((value >> 24) as u8)); // 10 + 30bit
        out.push(((value >> 16) & 0xFF) as u8);
        out.push(((value >> 8) & 0xFF) as u8);
        out.push((value & 0xFF) as u8);
    } else {
        // 11 + 62bit
        out.push(0xC0 | ((value >> 56) as u8));
        out.push(((value >> 48) & 0xFF) as u8);
        out.push(((value >> 40) & 0xFF) as u8);
        out.push(((value >> 32) & 0xFF) as u8);
        out.push(((value >> 24) & 0xFF) as u8);
        out.push(((value >> 16) & 0xFF) as u8);
        out.push(((value >> 8) & 0xFF) as u8);
        out.push((value & 0xFF) as u8);
    }
}

/// varint 解码（返回 (值, 消耗字节数)），失败返回 None
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    match first >> 6 {
        0 => Some(((first & 0x3F) as u64, 1)),
        1 => {
            if buf.len() < 2 {
                return None;
            }
            let v = ((first & 0x3F) as u64) << 8 | buf[1] as u64;
            Some((v, 2))
        }
        2 => {
            if buf.len() < 4 {
                return None;
            }
            let mut v = (first & 0x3F) as u64;
            for i in 1..4 {
                v = (v << 8) | buf[i] as u64;
            }
            Some((v, 4))
        }
        _ => {
            if buf.len() < 8 {
                return None;
            }
            let mut v = (first & 0x3F) as u64;
            for i in 1..8 {
                v = (v << 8) | buf[i] as u64;
            }
            Some((v, 8))
        }
    }
}

/// 编码 STREAM 帧（应用数据）
///
/// - stream_id: 流 ID（0 保留，1..=65535 可用）
/// - offset: 流内字节偏移（用于流内乱序重组）
/// - data: 应用数据（≤ MAX_UDP_PAYLOAD - 头部开销）
/// - fin: 该帧是否携带 FIN（流的发送端关闭）
pub fn encode_stream(buf: &mut Vec<u8>, stream_id: u32, offset: u64, data: &[u8], fin: bool) {
    // 帧类型：0x04 | (fin ? 0x01 : 0x00)
    buf.push(if fin { 0x04 | STREAM_FIN } else { 0x04 });
    encode_varint(stream_id as u64, buf);
    encode_varint(offset, buf);
    encode_varint(data.len() as u64, buf);
    buf.extend_from_slice(data);
}

/// 解析 STREAM 帧（返回 (end_stream, stream_id, offset, data)）
pub fn decode_stream(buf: &[u8]) -> io::Result<(bool, u32, u64, &[u8])> {
    let first = *buf.first().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, "空帧"))?;
    // 帧类型：0x04 或 0x05（0x05 = 带 FIN 标志）
    if first != 0x04 && first != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非 STREAM 帧"));
    }
    let fin = (first & STREAM_FIN) != 0;
    let mut pos = 1;
    let (stream_id, n) = decode_varint(&buf[pos..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "流 ID varint 无效"))?;
    pos += n;
    let (offset, n) = decode_varint(&buf[pos..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "偏移 varint 无效"))?;
    pos += n;
    let (len, n) = decode_varint(&buf[pos..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "长度 varint 无效"))?;
    pos += n;
    let len = len as usize;
    if pos + len > buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "STREAM 数据超界"));
    }
    let data = &buf[pos..pos + len];
    Ok((fin, stream_id as u32, offset, data))
}

/// 编码 ACK 帧（确认已收最大序号）
pub fn encode_ack(buf: &mut Vec<u8>, largest_acked: u64, delay_us: u32) {
    buf.push(FrameType::Ack as u8);
    encode_varint(largest_acked, buf);
    encode_varint(delay_us as u64, buf);
}

/// 解析 ACK 帧（返回 (最大已确认序号, 延迟微秒)）
pub fn decode_ack(buf: &[u8]) -> io::Result<(u64, u32)> {
    if buf.is_empty() || buf[0] != FrameType::Ack as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非 ACK 帧"));
    }
    let (largest, n1) = decode_varint(&buf[1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ACK varint 无效"))?;
    let (delay, _) = decode_varint(&buf[1 + n1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "延迟 varint 无效"))?;
    Ok((largest, delay as u32))
}

/// 编码 PING/PONG 帧
///
/// PING 无负载（探测/RTT 测量起点）；PONG 回显发起方时间戳载荷。
///（P1.5 心跳/RTT 测量接入时启用）
#[allow(dead_code)]
pub fn encode_ping(buf: &mut Vec<u8>) {
    buf.push(FrameType::Ping as u8);
}

/// 编码 PONG（回显载荷）
pub fn encode_pong(buf: &mut Vec<u8>, echo: &[u8]) {
    buf.push(FrameType::Pong as u8);
    encode_varint(echo.len() as u64, buf);
    buf.extend_from_slice(echo);
}

/// 解析 PONG（返回回显载荷）
pub fn decode_pong(buf: &[u8]) -> io::Result<&[u8]> {
    if buf.is_empty() || buf[0] != FrameType::Pong as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非 PONG 帧"));
    }
    let (len, n) = decode_varint(&buf[1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PONG varint 无效"))?;
    let start = 1 + n;
    let end = start + len as usize;
    if end > buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "PONG 超界"));
    }
    Ok(&buf[start..end])
}

/// 编码 RST_STREAM 帧（流重置）
///（P1.5 流级复位接入时启用）
#[allow(dead_code)]
pub fn encode_rst_stream(buf: &mut Vec<u8>, stream_id: u32, error_code: u32) {
    buf.push(FrameType::RstStream as u8);
    encode_varint(stream_id as u64, buf);
    encode_varint(error_code as u64, buf);
}

/// 解析 RST_STREAM 帧
pub fn decode_rst_stream(buf: &[u8]) -> io::Result<(u32, u32)> {
    if buf.is_empty() || buf[0] != FrameType::RstStream as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非 RST_STREAM 帧"));
    }
    let (sid, n1) = decode_varint(&buf[1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "流 ID varint 无效"))?;
    let (code, _) = decode_varint(&buf[1 + n1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "错误码 varint 无效"))?;
    Ok((sid as u32, code as u32))
}

/// 编码 MAX_DATA（连接级流控窗口更新）
///（P1.5 精确流控接入时启用；当前单连接共享拥控窗口由 BBR 承担）
#[allow(dead_code)]
pub fn encode_max_data(buf: &mut Vec<u8>, max_data: u64) {
    buf.push(FrameType::MaxData as u8);
    encode_varint(max_data, buf);
}

/// 解析 MAX_DATA
pub fn decode_max_data(buf: &[u8]) -> io::Result<u64> {
    if buf.is_empty() || buf[0] != FrameType::MaxData as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非 MAX_DATA 帧"));
    }
    let (v, _) = decode_varint(&buf[1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "varint 无效"))?;
    Ok(v)
}

/// 编码 MAX_STREAM_DATA（流级流控窗口更新）
///（P1.5 精确流控接入时启用；当前单连接共享拥控窗口由 BBR 承担）
#[allow(dead_code)]
pub fn encode_max_stream_data(buf: &mut Vec<u8>, stream_id: u32, max_data: u64) {
    buf.push(FrameType::MaxStreamData as u8);
    encode_varint(stream_id as u64, buf);
    encode_varint(max_data, buf);
}

/// 解析 MAX_STREAM_DATA
pub fn decode_max_stream_data(buf: &[u8]) -> io::Result<(u32, u64)> {
    if buf.is_empty() || buf[0] != FrameType::MaxStreamData as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非 MAX_STREAM_DATA 帧"));
    }
    let (sid, n1) = decode_varint(&buf[1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "流 ID varint 无效"))?;
    let (max, _) = decode_varint(&buf[1 + n1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "varint 无效"))?;
    Ok((sid as u32, max))
}

/// 编码握手帧（认证/密钥协商载荷，包装 SRT 特征握手内容）
pub fn encode_handshake(buf: &mut Vec<u8>, payload: &[u8]) {
    buf.push(FrameType::Handshake as u8);
    encode_varint(payload.len() as u64, buf);
    buf.extend_from_slice(payload);
}

/// 解析握手帧（返回握手载荷）
pub fn decode_handshake(buf: &[u8]) -> io::Result<&[u8]> {
    if buf.is_empty() || buf[0] != FrameType::Handshake as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非握手帧"));
    }
    let (len, n) = decode_varint(&buf[1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "varint 无效"))?;
    let start = 1 + n;
    let end = start + len as usize;
    if end > buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "握手帧超界"));
    }
    Ok(&buf[start..end])
}

/// 尝试解析一个完整帧，返回 (帧类型, 帧负载)，不足一帧返回 Ok(None)
/// （用于 UDP 数据报内可能包含的多个帧或半帧的缓冲重组）
pub fn try_parse_frame(buf: &[u8]) -> io::Result<Option<(FrameType, &[u8])>> {
    if buf.is_empty() {
        return Ok(None);
    }
    let ftype = FrameType::from_byte(buf[0]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "未知帧类型"))?;
    // 各帧的最小长度校验
    match ftype {
        FrameType::Ping => Ok(Some((ftype, &buf[1..]))),
        FrameType::Ack => {
            if decode_ack(buf).is_ok() {
                Ok(Some((ftype, &buf[1..])))
            } else {
                Ok(None)
            }
        }
        FrameType::Pong => {
            if decode_pong(buf).is_ok() {
                Ok(Some((ftype, &buf[1..])))
            } else {
                Ok(None)
            }
        }
        FrameType::Stream => {
            if decode_stream(buf).is_ok() {
                Ok(Some((ftype, &buf[1..])))
            } else {
                Ok(None)
            }
        }
        FrameType::RstStream => {
            if decode_rst_stream(buf).is_ok() {
                Ok(Some((ftype, &buf[1..])))
            } else {
                Ok(None)
            }
        }
        FrameType::MaxData => {
            if decode_max_data(buf).is_ok() {
                Ok(Some((ftype, &buf[1..])))
            } else {
                Ok(None)
            }
        }
        FrameType::MaxStreamData => {
            if decode_max_stream_data(buf).is_ok() {
                Ok(Some((ftype, &buf[1..])))
            } else {
                Ok(None)
            }
        }
        FrameType::Handshake => {
            if decode_handshake(buf).is_ok() {
                Ok(Some((ftype, &buf[1..])))
            } else {
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// varint 编解码往返 + 边界值
    #[test]
    fn test_varint_roundtrip() {
        for v in [0u64, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824, u32::MAX as u64] {
            let mut out = Vec::new();
            encode_varint(v, &mut out);
            let (decoded, used) = decode_varint(&out).expect("解码失败");
            assert_eq!(decoded, v, "varint 值不匹配: {v}");
            assert_eq!(used, out.len(), "varint 消耗字节数不匹配: {v}");
        }
    }

    /// STREAM 帧编解码往返（含 FIN）
    #[test]
    fn test_stream_roundtrip() {
        let data = b"hello quic stream";
        let mut buf = Vec::new();
        encode_stream(&mut buf, 42, 0, data, true);
        let (fin, sid, offset, decoded) = decode_stream(&buf).expect("解码失败");
        assert!(fin);
        assert_eq!(sid, 42);
        assert_eq!(offset, 0);
        assert_eq!(decoded, data);
    }

    /// STREAM 帧带偏移（乱序重组用）
    #[test]
    fn test_stream_offset() {
        let mut buf = Vec::new();
        encode_stream(&mut buf, 7, 4096, &[1, 2, 3], false);
        let (fin, sid, offset, data) = decode_stream(&buf).expect("解码失败");
        assert!(!fin);
        assert_eq!(sid, 7);
        assert_eq!(offset, 4096);
        assert_eq!(data, &[1, 2, 3]);
    }

    /// ACK / PONG / MAX_DATA / 握手帧编解码往返
    #[test]
    fn test_ctrl_frames_roundtrip() {
        let mut ack = Vec::new();
        encode_ack(&mut ack, 12345, 250);
        assert_eq!(decode_ack(&ack).unwrap(), (12345, 250));

        let mut pong = Vec::new();
        let echo = [0xde, 0xad, 0xbe, 0xef];
        encode_pong(&mut pong, &echo);
        assert_eq!(decode_pong(&pong).unwrap(), &echo);

        let mut md = Vec::new();
        encode_max_data(&mut md, 1_000_000);
        assert_eq!(decode_max_data(&md).unwrap(), 1_000_000);

        let mut msd = Vec::new();
        encode_max_stream_data(&mut msd, 99, 555_555);
        assert_eq!(decode_max_stream_data(&msd).unwrap(), (99, 555_555));

        let mut hs = Vec::new();
        encode_handshake(&mut hs, &[1, 2, 3, 4]);
        assert_eq!(decode_handshake(&hs).unwrap(), &[1, 2, 3, 4]);
    }

    /// 非法输入拒绝
    #[test]
    fn test_invalid_inputs() {
        // 空 buffer
        assert!(decode_varint(&[]).is_none());
        // 不完整 varint（声明 2 字节但只有 1）
        assert!(decode_varint(&[0x40]).is_none());
        // 非 STREAM 帧
        let bad = [0x99, 0x01];
        assert!(decode_stream(&bad).is_err());
        // STREAM 数据超界
        let mut buf = Vec::new();
        encode_stream(&mut buf, 1, 0, &[1, 2, 3], false);
        buf.truncate(buf.len() - 2); // 截掉部分数据
        assert!(decode_stream(&buf).is_err());
    }

    /// 帧类型解析（含带 FIN 的 Stream=0x05）
    #[test]
    fn test_frame_type_parse() {
        assert_eq!(FrameType::from_byte(0x01), Some(FrameType::Ping));
        assert_eq!(FrameType::from_byte(0x02), Some(FrameType::Ack));
        assert_eq!(FrameType::from_byte(0x04), Some(FrameType::Stream));
        assert_eq!(FrameType::from_byte(0x05), Some(FrameType::Stream)); // FIN 位
        assert_eq!(FrameType::from_byte(0xff), None);
    }
}