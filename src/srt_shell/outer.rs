//! srt_shell/outer.rs — 外层 SRT 壳封装（16B 头 + 内层传输帧）
//!
//! 每个 UDP 数据报 = SRT 16B 头 + 内层传输帧（自研 QUIC 语义，quic/packet.rs）。
//! 封装/解封装是本外壳的核心：对 DPI 而言，每个包都是合法的 SRT/UDT 结构。
//!
//! 时间戳：微秒级（TSBPD 风格，仿真 SRT 实时流的时间纹理）
//! socket ID：握手协商的随机 ID（客户端/服务端各一，包内互填对端）

use super::header::{
    encode_ctrl_header, encode_data_header, parse_header, SRT_HEADER_LEN, SRT_MSS,
    MSG_ACK, MSG_HANDSHAKE,
};

/// 当前 socket ID（简化：进程级单连接，握手后互填；多连接用 hash 区分）
pub const SOCKET_ID: u32 = 0x5A11; // 固定演示值（正式实现由握手协商）

/// 微秒时间戳（TSBPD 风格，无符号回绕由对端处理）
pub fn now_ts_us() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // 取低 32 位微秒（回绕约 71 分钟，SRT 同款语义）
    (now.as_micros() & 0xFFFF_FFFF) as u32
}

/// v1 数据包封装已由 encode_data_packet_v2 取代（v2 显式传包号写 SEQ 字段）；
/// v1 版本删除（内部 msg_seq 全局计数器与多连接池语义冲突）。

/// 封装一个控制包（握手/ACK）
pub fn encode_ctrl_packet(msg_type: u32, ext: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(SRT_HEADER_LEN + payload.len());
    let hdr = encode_ctrl_header(msg_type, ext, now_ts_us(), SOCKET_ID);
    pkt.extend_from_slice(&hdr);
    pkt.extend_from_slice(payload);
    pkt
}

/// 解封装：输入 UDP 负载，输出 (is_ctrl, msg_type, inner)
/// 不足 16B 返回 None（非法包丢弃）
pub fn decode_packet(buf: &[u8]) -> Option<(bool, u32, &[u8])> {
    if buf.len() < SRT_HEADER_LEN {
        return None;
    }
    let hdr: [u8; SRT_HEADER_LEN] = buf[..SRT_HEADER_LEN].try_into().ok()?;
    let (is_ctrl, msg_type, _, _) = parse_header(&hdr);
    let inner = &buf[SRT_HEADER_LEN..];
    // 控制包类型校验（防垃圾包：只接受合法的 SRT 类型）
    if is_ctrl {
        if msg_type != MSG_HANDSHAKE && msg_type != MSG_ACK {
            return None;
        }
    }
    Some((is_ctrl, msg_type, inner))
}

// v1 msg_seq 已删：v2 数据包号由连接级 next_pkt_num 分配（多连接池各自独立计数）

// ============================================================================
// v2 传输层接口（2026-08-20 内核重写）：包号承载在 SEQ 字段
// ============================================================================

/// v2 封装数据包（显式包号写 SEQ 字段--传输层确认键）
///
/// 真 SRT 的 SEQ 本来就是包序号（每连接递增），v2 内核把它作为 ACK 确认键：
/// 接收方从外壳直接读包号，ACK 区间语义与 RFC9000 完全对齐。
pub fn encode_data_packet_v2(inner: &[u8], pkt_num: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(SRT_HEADER_LEN + inner.len());
    let hdr = encode_data_header(pkt_num, now_ts_us(), SOCKET_ID, 0);
    pkt.extend_from_slice(&hdr);
    pkt.extend_from_slice(inner);
    pkt
}

/// v2 封装 ACK 控制包（明文控制壳承载内层 ACK 区间帧）
///
/// 真 SRT 的 ACK 是控制包（0x80 02 00 00）；v2 的内层 ACK 帧装在它的
/// 载荷里（DPI 看到的是标准 SRT ACK 外形）。控制壳不加密（SRT 同款）。
pub fn encode_ack_ctrl_packet(inner: &[u8]) -> Vec<u8> {
    encode_ctrl_packet(MSG_ACK, 0, inner)
}

/// v2 解封装（返回 (包号, is_ctrl, msg_type, inner)）
///
/// 数据包：包号 = SEQ 字段（bit30..0，bit31=0）
/// 控制包：包号无意义（返回 0），按 msg_type 分流
/// 非法包（<16B / 未知控制类型）返回 None
pub fn decode_packet_v2(buf: &[u8]) -> Option<(u64, bool, u32, &[u8])> {
    if buf.len() < SRT_HEADER_LEN {
        return None;
    }
    let hdr: [u8; SRT_HEADER_LEN] = buf[..SRT_HEADER_LEN].try_into().ok()?;
    let (is_ctrl, msg_type, _ts, _sid) = parse_header(&hdr);
    let inner = &buf[SRT_HEADER_LEN..];
    if is_ctrl && msg_type != MSG_HANDSHAKE && msg_type != MSG_ACK {
        return None; // 未知控制类型（防垃圾包）
    }
    let seqno = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let pkt_num = if is_ctrl { 0 } else { (seqno & 0x7FFF_FFFF) as u64 };
    Some((pkt_num, is_ctrl, msg_type, inner))
}

/// 最大可发 payload（保持包长 ≤ MSS + 头部）
///（P1.5 包长纹理拟真接入时启用）
#[allow(dead_code)]
pub fn max_inner_len() -> usize {
    SRT_MSS as usize - SRT_HEADER_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 数据包封装/解封装往返（v2：包号写 SEQ 字段）
    #[test]
    fn test_data_roundtrip() {
        let inner = b"inner transport frame";
        let pkt = encode_data_packet_v2(inner, 42);
        assert_eq!(pkt.len(), SRT_HEADER_LEN + inner.len());
        let (pkt_num, is_ctrl, msg_type, out) = decode_packet_v2(&pkt).expect("解封装失败");
        assert!(!is_ctrl);
        assert_eq!(pkt_num, 42, "包号应从 SEQ 字段读回");
        assert_eq!(msg_type, 0);
        assert_eq!(out, inner);
    }

    /// 控制包（握手 0x80 开头 / ACK 0x80 02）
    #[test]
    fn test_ctrl_roundtrip() {
        let pkt = encode_ctrl_packet(MSG_HANDSHAKE, 0, &[]);
        assert_eq!(&pkt[0..4], &[0x80, 0, 0, 0], "握手首包应 0x80 00 00 00");
        let (is_ctrl, msg_type, _) = decode_packet(&pkt).unwrap();
        assert!(is_ctrl);
        assert_eq!(msg_type, MSG_HANDSHAKE);

        let ack = encode_ctrl_packet(MSG_ACK, 0, &[1, 2, 3]);
        assert_eq!(&ack[0..4], &[0x80, 0x02, 0, 0], "ACK 应 0x80 02 00 00");
        let (is_ctrl, msg_type, inner) = decode_packet(&ack).unwrap();
        assert!(is_ctrl);
        assert_eq!(msg_type, MSG_ACK);
        assert_eq!(inner, &[1, 2, 3]);
    }

    /// 非法包（<16B / 未知控制类型）丢弃
    #[test]
    fn test_invalid_packets() {
        assert!(decode_packet(&[0u8; 5]).is_none(), "过短包应丢弃");
        // 控制包类型未知（非 HANDSHAKE/ACK）应被拒
        let bad = encode_ctrl_packet(MSG_HANDSHAKE + 100, 0, &[]);
        assert!(decode_packet(&bad).is_none(), "未知控制类型应拒绝");
        // 合法控制包 + 未知扩展仍应接受（扩展不影响主类型）
        let ok = encode_ctrl_packet(MSG_ACK, 0xbeef, &[]);
        assert!(decode_packet(&ok).is_some());
    }
}