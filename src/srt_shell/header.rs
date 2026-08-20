//! srt_shell/header.rs — SRT 16B 固定头（外层壳）
//!
//! 对齐 libsrt 的线协议头部（packet.h SRT_PH_* 字段布局），DPI 据此识别 SRT：
//!
//! ```
//! ┌─────────────┬─────────────┬─────────────┬─────────────┐
//! │ 0-3  SEQNO  │ 4-7  MSGNO  │ 8-11  TS    │ 12-15 ID    │  （均大端）
//! └─────────────┴─────────────┴─────────────┴─────────────┘
//! ```
//!
//! - SEQNO：bit31=0 数据包 / =1 控制包；bit30..16 = 消息类型；bit15..0 = 扩展
//! - MSGNO：bit31-30 边界；bit29 顺序要求；bit28-27 加密 key 标志；bit26 重传；bit25-0 消息序号
//! - TIMESTAMP：32 位微秒时间戳（TSBPD）
//! - ID：目标 socket ID
//!
//! 常量对齐 libsrt 源码：
//! - 控制包类型：HANDSHAKE=0, ACK=2（packet.cpp pack(UMSG_*) 分支）
//! - 版本 = 4（HS_VERSION_UDT4，handshake.h）
//! - ReqType：URQ_INDUCTION=1（握手首包）
//! - MSS = 1500（默认，payload 1316 = 1500 - IP20 - UDP8 - SRT16）

/// SRT 头部长度（固定 16 字节）
pub const SRT_HEADER_LEN: usize = 16;

/// SEQNO 控制位（bit31）
pub const SEQ_CONTROL: u32 = 0x8000_0000;
/// 控制包消息类型位掩码（bit30..16）
pub const MSG_TYPE_MASK: u32 = 0x7FFF_0000;

/// 控制消息类型
pub const MSG_HANDSHAKE: u32 = 0; // UMSG_HANDSHAKE
pub const MSG_ACK: u32 = 2; // UMSG_ACK
///（P1.5 keepalive/丢包报告拟真接入时启用）
#[allow(dead_code)]
pub const MSG_NACK: u32 = 3; // UMSG_LOSSREPORT

/// SRT/UDT 版本（握手第二 word；P1.5 深度握手拟真接入时启用）
#[allow(dead_code)]
pub const HS_VERSION_UDT4: u32 = 4;

/// 握手请求类型（P1.5 深度握手拟真接入时启用）
#[allow(dead_code)]
pub const URQ_INDUCTION: u32 = 1; // 客户端首包（握手协商起点）

/// 默认 MSS / payload（P1.5 包长纹理拟真接入时启用）
#[allow(dead_code)]
pub const SRT_MSS: u32 = 1500;
#[allow(dead_code)]
pub const SRT_DEF_PAYLOAD: usize = 1316;

/// 编码 SRT 控制包头（首 16B）
///
/// - msg_type: MSG_HANDSHAKE / MSG_ACK / ...
/// - ext: 扩展类型（bit15..0）
/// - ts_us: 时间戳（微秒）
/// - socket_id: 目标 socket ID
pub fn encode_ctrl_header(
    msg_type: u32,
    ext: u32,
    ts_us: u32,
    socket_id: u32,
) -> [u8; SRT_HEADER_LEN] {
    let seqno = SEQ_CONTROL | ((msg_type & 0x7FFF) << 16) | (ext & 0xFFFF);
    let mut h = [0u8; SRT_HEADER_LEN];
    h[0..4].copy_from_slice(&seqno.to_be_bytes());
    h[4..8].copy_from_slice(&0u32.to_be_bytes()); // MSGNO（控制包无附加）
    h[8..12].copy_from_slice(&ts_us.to_be_bytes());
    h[12..16].copy_from_slice(&socket_id.to_be_bytes());
    h
}

/// 编码 SRT 数据包头（bit31=0）
///
/// - msg_seq: 消息序号（bit25..0）
/// - ts_us: 时间戳（微秒）
/// - socket_id: 目标 socket ID
/// - flags: MSGNO 的高位标志（顺序/加密 key/重传 等）
pub fn encode_data_header(
    msg_seq: u32,
    ts_us: u32,
    socket_id: u32,
    flags: u32,
) -> [u8; SRT_HEADER_LEN] {
    let seqno = msg_seq & !SEQ_CONTROL; // 数据包 bit31=0
    let msgno = (flags & 0xF000_0000) | (msg_seq & 0x03FF_FFFF);
    let mut h = [0u8; SRT_HEADER_LEN];
    h[0..4].copy_from_slice(&seqno.to_be_bytes());
    h[4..8].copy_from_slice(&msgno.to_be_bytes());
    h[8..12].copy_from_slice(&ts_us.to_be_bytes());
    h[12..16].copy_from_slice(&socket_id.to_be_bytes());
    h
}

/// 解析 SRT 包头，返回 (is_ctrl, msg_type_or_0, ts_us, socket_id)
pub fn parse_header(h: &[u8; SRT_HEADER_LEN]) -> (bool, u32, u32, u32) {
    let seqno = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    let is_ctrl = (seqno & SEQ_CONTROL) != 0;
    let msg_type = if is_ctrl { (seqno & MSG_TYPE_MASK) >> 16 } else { 0 };
    let ts_us = u32::from_be_bytes([h[8], h[9], h[10], h[11]]);
    let socket_id = u32::from_be_bytes([h[12], h[13], h[14], h[15]]);
    (is_ctrl, msg_type, ts_us, socket_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 首包应为 0x80 00 00 00（控制 + HANDSHAKE）
    #[test]
    fn test_handshake_first_packet() {
        let hdr = encode_ctrl_header(MSG_HANDSHAKE, 0, 0, 0);
        assert_eq!(hdr[0], 0x80, "首字节应为 0x80（控制位）");
        assert_eq!(&hdr[0..4], &[0x80, 0x00, 0x00, 0x00], "首包应 0x80 00 00 00");
    }

    /// ACK 包应为 0x80 02 00 00
    #[test]
    fn test_ack_first_bytes() {
        let hdr = encode_ctrl_header(MSG_ACK, 0, 0, 0);
        assert_eq!(&hdr[0..4], &[0x80, 0x02, 0x00, 0x00], "ACK 包应 0x80 02 00 00");
    }

    /// 数据包 bit31=0（首字节 < 0x80）
    #[test]
    fn test_data_header_bit0() {
        let hdr = encode_data_header(1, 1000, 0xdead, 0);
        assert!(hdr[0] < 0x80, "数据包首字节应 < 0x80（bit31=0），实际 0x{:02x}", hdr[0]);
    }

    /// 解析往返
    #[test]
    fn test_parse_roundtrip() {
        let hdr = encode_ctrl_header(MSG_ACK, 5, 123456, 0xabcd);
        let (is_ctrl, msg_type, ts, sid) = parse_header(&hdr);
        assert!(is_ctrl);
        assert_eq!(msg_type, MSG_ACK);
        assert_eq!(ts, 123456);
        assert_eq!(sid, 0xabcd);
        // 数据包
        let hdr2 = encode_data_header(42, 999, 0x1111, 0);
        let (is_ctrl2, msg_type2, ts2, _) = parse_header(&hdr2);
        assert!(!is_ctrl2);
        assert_eq!(msg_type2, 0);
        assert_eq!(ts2, 999);
    }
}