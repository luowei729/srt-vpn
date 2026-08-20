//! quic/packet.rs - 自研 QUIC 语义传输内核 v2：帧编解码
//!
//! 2026-08-20 v2 完整重写（传输层质量重构）：
//! v1 的 ACK 是"单值确认"（先固定 0，后改字节偏移 + FIN+1 hack），确认键
//! （包号）是发送方私有的、接收方永远看不到，收发两侧语义对不齐，补丁
//! 三轮仍无法覆盖丢包场景（netem 2% 丢包即卡死）。
//! v2 回归标准 QUIC/RFC9000 语义：
//! - **包号放 SRT 外壳 SEQ 字段**（真 SRT 的 SEQ 本来就是包序号），
//!   接收方直接按包号确认，与标准 ACK 语义完全闭环
//! - ACK 帧升级为**区间确认**（largest + ACK Ranges，RFC9000 §19.3 风格），
//!   SACK 能力内建：区间之间的 gap 即丢包，发送方立即快速重传
//! - 帧类型直接判首字节（删 v1 try_parse_frame 中间层）
//! - 删除未用的 MAX_DATA/MAX_STREAM_DATA 帧流控（拥控由 BBR 承担）
//!
//! 帧布局（大端 varint）：
//!   STREAM:  [0x04|FIN bit0][流 ID][流内偏移][长度][数据]
//!   ACK:     [0x02][largest][delay_us][range_count]
//!            [首个 range 长度]{[gap][range 长度]}×(range_count-1)
//!   PING:    [0x01][载荷长度][载荷]（心跳时间戳 8B）
//!   PONG:    [0x03][载荷长度][载荷]（回显 PING 载荷）
//!   RST:     [0x0b][流 ID][错误码]
//!   握手:    [0xf0][载荷]
//!
//! ACK Ranges 语义（从 largest 向小排，学 RFC9000 §19.3）：
//!   首个 range 覆盖 [largest - first_len + 1, largest]
//!   后续每个 range：先跳过 gap 个未收包（gap >= 1），再连续 len 个已收包
//!   例：已收 {1,2,3, 5,6, 9} -> largest=9，降序区间 [(9,9), (5,6), (1,3)]
//!   编码：first_len=1（段 [9,9]），gap=2（7,8 未收），len=2（段 [5,6]），
//!         gap=1（4 未收），len=3（段 [1,3]）

use std::io;

/// 连接级最大 UDP 负载（P1.5 包长纹理接入时启用；当前取块大小由上层控制）
#[allow(dead_code)]
pub const MAX_UDP_PAYLOAD: usize = 1316;

/// 帧类型（传输层，非复用层会话帧）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// PING（保活/RTT 探测，载荷=微秒时间戳）
    Ping = 0x01,
    /// ACK（区间确认，走控制壳）
    Ack = 0x02,
    /// PONG（PING 回显）
    Pong = 0x03,
    /// STREAM（应用数据；0x05 = Stream+FIN）
    Stream = 0x04,
    /// RST_STREAM（流重置）
    RstStream = 0x0b,
    /// 握手帧（认证载荷，包装 SRT 特征握手）
    Handshake = 0xf0,
}

impl FrameType {
    /// 从首字节解析帧类型
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Ping),
            0x02 => Some(Self::Ack),
            0x03 => Some(Self::Pong),
            0x04 | 0x05 => Some(Self::Stream), // 0x05 = Stream+FIN
            0x0b => Some(Self::RstStream),
            0xf0 => Some(Self::Handshake),
            _ => None,
        }
    }
}

/// STREAM 帧标志（低 1 位内嵌在帧类型字节）
pub const STREAM_FIN: u8 = 0x01; // 帧类型 0x05 = Stream + FIN

// ============================================================================
// varint（RFC 9000 §16 变长整数，v1 实现已验证，保留）
// ============================================================================

/// varint 编码（QUIC variable-length integer）
///
/// 首字节高 2 位表示长度：00=1字节(6bit) 01=2字节(14bit) 10=4字节(30bit) 11=8字节(62bit)
pub fn encode_varint(value: u64, out: &mut Vec<u8>) {
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

// ============================================================================
// STREAM 帧（v1 保留：多流 + offset 重组语义正确）
// ============================================================================

/// 编码 STREAM 帧
/// - stream_id: 流 ID（0 保留，1..=65535 可用）
/// - offset: 流内字节偏移（流内乱序重组）
/// - data: 应用数据（≤ MAX_UDP_PAYLOAD - 头部开销）
/// - fin: 该帧是否携带 FIN（流的发送端关闭）
pub fn encode_stream(buf: &mut Vec<u8>, stream_id: u32, offset: u64, data: &[u8], fin: bool) {
    buf.push(if fin { 0x04 | STREAM_FIN } else { 0x04 });
    encode_varint(stream_id as u64, buf);
    encode_varint(offset, buf);
    encode_varint(data.len() as u64, buf);
    buf.extend_from_slice(data);
}

/// 解析 STREAM 帧（返回 (end_stream, stream_id, offset, data)）
pub fn decode_stream(buf: &[u8]) -> io::Result<(bool, u32, u64, &[u8])> {
    let first = *buf.first().ok_or(io::Error::new(io::ErrorKind::UnexpectedEof, "空帧"))?;
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
    Ok((fin, stream_id as u32, offset, &buf[pos..pos + len]))
}

// ============================================================================
// ACK 帧 v2（区间确认，RFC9000 §19.3 风格）
// ============================================================================

/// 编码 ACK 帧（区间确认）
///
/// - largest: 最大已确认包号
/// - delay_us: ACK 延迟（RTT 修正用，微秒；0 = 立即 ACK）
/// - ranges: 已收包号区间（**降序**，互不相邻；空 = 无确认纯保活）
///
/// 线格式：[0x02][largest][delay][count][first_len]{[gap][len]}...
/// 首段 [largest-first_len+1, largest]；后续段跳 gap 个未收再连续 len 个。
pub fn encode_ack_ranges(buf: &mut Vec<u8>, largest: u64, delay_us: u32, ranges: &[(u64, u64)]) {
    buf.push(FrameType::Ack as u8);
    encode_varint(largest, buf);
    encode_varint(delay_us as u64, buf);
    encode_varint(ranges.len() as u64, buf);
    let mut prev_low: u64 = 0;
    for (i, (low, high)) in ranges.iter().enumerate() {
        debug_assert!(*low <= *high, "区间下界应 <= 上界");
        if i == 0 {
            encode_varint(high - low + 1, buf);
        } else {
            let gap = prev_low.saturating_sub(high + 1);
            encode_varint(gap, buf);
            encode_varint(high - low + 1, buf);
        }
        prev_low = *low;
    }
}

/// 解析 ACK 帧（返回 (largest, delay_us, 区间列表降序)）
pub fn decode_ack_ranges(buf: &[u8]) -> io::Result<(u64, u32, Vec<(u64, u64)>)> {
    if buf.is_empty() || buf[0] != FrameType::Ack as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非 ACK 帧"));
    }
    let mut pos = 1;
    let (largest, n) = decode_varint(&buf[pos..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "largest varint 无效"))?;
    pos += n;
    let (delay, n) = decode_varint(&buf[pos..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "delay varint 无效"))?;
    pos += n;
    let (count, n) = decode_varint(&buf[pos..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "range_count varint 无效"))?;
    pos += n;
    let count = count.min(256) as usize; // 防御：上限 256 段
    let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(count);
    if count == 0 {
        return Ok((largest, delay as u32, ranges));
    }
    // 首段
    let (first_len, n) = decode_varint(&buf.get(pos..).unwrap_or(&[])).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "first range len varint 无效"))?;
    pos += n;
    if first_len == 0 || first_len > largest + 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "首段长度非法（0 或超出 largest）"));
    }
    let low = largest + 1 - first_len;
    ranges.push((low, largest));
    let mut prev_low = low;
    // 后续段：[gap][len]
    for _ in 1..count {
        let (gap, n) = decode_varint(&buf.get(pos..).unwrap_or(&[])).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "gap varint 无效"))?;
        pos += n;
        let (len, n) = decode_varint(&buf.get(pos..).unwrap_or(&[])).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "range len varint 无效"))?;
        pos += n;
        if len == 0 || gap >= prev_low {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "gap/range 长度非法（越界）"));
        }
        let new_high = prev_low - gap - 1;
        if len > new_high + 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "后续段长度非法（越过 0）"));
        }
        let new_low = new_high + 1 - len;
        ranges.push((new_low, new_high));
        prev_low = new_low;
    }
    Ok((largest, delay as u32, ranges))
}

// ============================================================================
// PING/PONG（心跳 RTT，载荷=微秒时间戳）
// ============================================================================

/// 编码 PING（载荷：发起方微秒时间戳，供 RTT 测量）
pub fn encode_ping(buf: &mut Vec<u8>, payload: &[u8]) {
    buf.push(FrameType::Ping as u8);
    encode_varint(payload.len() as u64, buf);
    buf.extend_from_slice(payload);
}

/// 解析 PING（返回载荷，PONG 原样回显）
pub fn decode_ping(buf: &[u8]) -> io::Result<&[u8]> {
    if buf.is_empty() || buf[0] != FrameType::Ping as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非 PING 帧"));
    }
    let (len, n) = decode_varint(&buf[1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PING varint 无效"))?;
    let start = 1 + n;
    let end = start + len as usize;
    if end > buf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "PING 超界"));
    }
    Ok(&buf[start..end])
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

// ============================================================================
// RST_STREAM / 握手（v1 保留）
// ============================================================================

/// 编码 RST_STREAM 帧（流重置；P1.5 per-session 流级复位接入时启用）
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
    let (sid, n) = decode_varint(&buf[1..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "流 ID varint 无效"))?;
    let (code, _) = decode_varint(&buf[1 + n..]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "错误码 varint 无效"))?;
    Ok((sid as u32, code as u32))
}

/// 编码握手帧（认证载荷）
pub fn encode_handshake(buf: &mut Vec<u8>, payload: &[u8]) {
    buf.push(FrameType::Handshake as u8);
    buf.extend_from_slice(payload);
}

/// 解析握手帧（返回载荷）
pub fn decode_handshake(buf: &[u8]) -> io::Result<&[u8]> {
    if buf.is_empty() || buf[0] != FrameType::Handshake as u8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "非握手帧"));
    }
    Ok(&buf[1..])
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

    /// STREAM 帧编解码往返（含 FIN / offset）
    #[test]
    fn test_stream_roundtrip() {
        let data = b"hello quic stream";
        let mut buf = Vec::new();
        encode_stream(&mut buf, 42, 4096, data, true);
        let (fin, sid, offset, decoded) = decode_stream(&buf).expect("解码失败");
        assert!(fin);
        assert_eq!(sid, 42);
        assert_eq!(offset, 4096);
        assert_eq!(decoded, data);
    }

    /// ACK 区间编解码往返（多段 + gap）
    #[test]
    fn test_ack_ranges_roundtrip() {
        // 已收 {1,2,3, 5,6, 9}：largest=9，降序区间 [(9,9), (5,6), (1,3)]
        let ranges = vec![(9u64, 9u64), (5, 6), (1, 3)];
        let mut buf = Vec::new();
        encode_ack_ranges(&mut buf, 9, 250, &ranges);
        let (l, d, out) = decode_ack_ranges(&buf).unwrap();
        assert_eq!(l, 9);
        assert_eq!(d, 250);
        assert_eq!(out, ranges, "ACK 区间应往返一致");
    }

    /// ACK 单段连续区间
    #[test]
    fn test_ack_single_range() {
        let ranges = vec![(0u64, 99u64)];
        let mut buf = Vec::new();
        encode_ack_ranges(&mut buf, 99, 0, &ranges);
        let (l, _, out) = decode_ack_ranges(&buf).unwrap();
        assert_eq!(l, 99);
        assert_eq!(out, ranges);
    }

    /// 空 ranges（纯保活 ACK）
    #[test]
    fn test_ack_empty_ranges() {
        let mut buf = Vec::new();
        encode_ack_ranges(&mut buf, 0, 0, &[]);
        let (l, d, out) = decode_ack_ranges(&buf).unwrap();
        assert_eq!(l, 0);
        assert_eq!(d, 0);
        assert!(out.is_empty());
    }

    /// 非法 ACK（非 ACK 头 / 截断）应报错
    #[test]
    fn test_ack_invalid() {
        // 非 ACK 帧头
        let mut buf = Vec::new();
        buf.push(0x04);
        assert!(decode_ack_ranges(&buf).is_err());
        // 截断：声称 2 段但只有 1 段数据
        let mut bad = Vec::new();
        bad.push(0x02);
        encode_varint(100, &mut bad);
        encode_varint(0, &mut bad);
        encode_varint(2, &mut bad); // count=2
        encode_varint(10, &mut bad); // first_len=10，后续段缺失
        assert!(decode_ack_ranges(&bad).is_err(), "截断的 ACK 应报错");
    }

    /// PING/PONG 载荷往返（心跳时间戳）
    #[test]
    fn test_ping_pong_roundtrip() {
        let ts = 12345678901234u64.to_be_bytes();
        let mut ping = Vec::new();
        encode_ping(&mut ping, &ts);
        assert_eq!(decode_ping(&ping).unwrap(), &ts, "PING 载荷往返一致");

        let mut pong = Vec::new();
        encode_pong(&mut pong, &ts);
        assert_eq!(decode_pong(&pong).unwrap(), &ts, "PONG 载荷往返一致");
    }

    /// RST / 握手帧往返
    #[test]
    fn test_rst_handshake_roundtrip() {
        let mut rst = Vec::new();
        encode_rst_stream(&mut rst, 7, 404);
        assert_eq!(decode_rst_stream(&rst).unwrap(), (7, 404));

        let mut hs = Vec::new();
        encode_handshake(&mut hs, &[1, 2, 3, 4]);
        assert_eq!(decode_handshake(&hs).unwrap(), &[1, 2, 3, 4]);
    }
}
