//! tunnel/multiplex.rs — 多路复用层（核心）
//!
//! 设计决策（Q7/Q14）：
//! - 单 SRT 连接 + 多路复用层：所有会话共享一条 SRT 隧道
//! - 单层可靠模型：可靠传输完全交给 SRT 层（udp_mode 配置 socket 参数）
//!   复用层只做：分帧（会话 ID 路由）+ 调度（公平排队）+ 窗口流控
//! - （2026-08-19 更新）TS 伪装层已移除，隧道帧直接作为 SRT 消息发送
//! - 帧头 v1（15 字节）：Magic + Version + Type + SessionID + Len + Seq + Flags
//!
//! 帧大小约束：帧头 15 字节 + payload ≤ 1316（SRT 消息上限），
//! 单帧数据 payload ≤ 1301 字节；大数据分片为多帧。

use std::sync::atomic::{AtomicU32, Ordering};

use super::{
    FrameType, FRAME_HEADER_LEN, PROTOCOL_VERSION, TUNNEL_MAGIC,
    FLAG_RELIABLE, FLAG_WINDOW,
};

/// 单帧数据 payload 上限（SRT 原生 payload 1316 - 帧头 15 = 1301）
/// 2026-08-19：移除 TS 伪装层，使用 SRT 官方默认 payload（1316B）。
pub const FRAME_DATA_MAX: usize = 1301;

/// 编码后的复用层帧
#[derive(Debug, Clone)]
pub struct Frame {
    /// 帧类型
    pub ftype: FrameType,
    /// 会话 ID
    pub session_id: u16,
    /// 序号（全局递增，流控/丢包检测用）
    /// （P1 后半段接入流控时启用）
    #[allow(dead_code)]
    pub seq: u32,
    /// 标志位
    /// （P1 后半段接入半关闭/流控时启用）
    #[allow(dead_code)]
    pub flags: u8,
    /// payload（已按会话路由）
    pub payload: Vec<u8>,
}

/// 多路复用编码器（发送方向）
pub struct MuxEncoder {
    /// 全局帧序号（原子递增，跨会话统一编号）
    seq: AtomicU32,
    /// 可靠模式标记（写入每帧标志位，对端据此适配）
    reliable: bool,
}

impl MuxEncoder {
    /// 创建编码器
    pub fn new(reliable: bool) -> Self {
        Self {
            seq: AtomicU32::new(0),
            reliable,
        }
    }

    /// 生成下一帧序号
    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// 编码一帧（输出直接作为 SRT 消息发送，2026-08-19 移除 TS 壳）
    ///
    /// payload 长度必须 ≤ FRAME_DATA_MAX（1301）
    pub fn encode_frame(&self, ftype: FrameType, session_id: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() <= FRAME_DATA_MAX, "帧 payload 超长: {} > 1301", payload.len());
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        // Magic
        frame.extend_from_slice(&TUNNEL_MAGIC);
        // Version
        frame.push(PROTOCOL_VERSION);
        // Type
        frame.push(ftype as u8);
        // Session ID (u16 BE)
        frame.extend_from_slice(&session_id.to_be_bytes());
        // Payload 长度 (u16 BE)
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        // 序号 (u32 BE)
        frame.extend_from_slice(&self.next_seq().to_be_bytes());
        // 标志位：可靠模式标记 + 调用方标志
        let mut f = flags;
        if self.reliable {
            f |= FLAG_RELIABLE;
        }
        frame.push(f);
        // Payload
        frame.extend_from_slice(payload);
        frame
    }

    /// 编码 ACK 帧（窗口推进信号，低频发送）
    /// payload: [窗口大小 u16 BE]
    /// （P1 后半段接入流控时启用）
    #[allow(dead_code)]
    pub fn encode_ack(&self, session_id: u16, window_size: u16) -> Vec<u8> {
        let mut payload = Vec::with_capacity(2);
        payload.extend_from_slice(&window_size.to_be_bytes());
        self.encode_frame(FrameType::Ack, session_id, FLAG_WINDOW, &payload)
    }

    /// 编码心跳帧
    ///
    /// 2026-08-19 审查补全（M8 RTT 测量）：
    /// 心跳载荷 = 发起方时间戳（8 字节 LE 毫秒）。
    /// 应答方原样回发同一载荷（pong），发起方收到后用 now - ts 即得 RTT。
    pub fn encode_heartbeat(&self) -> Vec<u8> {
        // 心跳带时间戳（8 字节 LE），对端回发同载荷可测 RTT
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let payload = ts.to_le_bytes();
        self.encode_frame(FrameType::Heartbeat, 0, 0, &payload)
    }
}

/// 从心跳帧载荷解析发起方时间戳（毫秒，M8 RTT 计算用）
/// 返回 None 表示载荷非法（非 8 字节）
///（生产路径心跳 RTT 由内核心跳承担；本函数供测试与 P1.5 心跳接入使用）
#[allow(dead_code)]
pub fn heartbeat_timestamp(payload: &[u8]) -> Option<i64> {
    if payload.len() != 8 {
        return None;
    }
    Some(i64::from_le_bytes(payload.try_into().ok()?))
}

/// 多路复用解码器（接收方向）
pub struct MuxDecoder {
    /// 上次收到的帧序号（乱序检测）
    last_seq: u32,
    /// 上次帧序号是否有效
    have_seq: bool,
}

impl Default for MuxDecoder {
    fn default() -> Self {
        Self {
            last_seq: 0,
            have_seq: false,
        }
    }
}

impl MuxDecoder {
    /// 创建解码器
    pub fn new() -> Self {
        Self::default()
    }

    /// 解码一帧（输入 TS payload，即 TS 包去头后的 184 字节）
    ///
    /// 返回 None：帧无效（Magic 不匹配 / 版本不对 / 长度不符）
    pub fn decode_frame(&mut self, ts_payload: &[u8]) -> Option<Frame> {
        if ts_payload.len() < FRAME_HEADER_LEN {
            return None;
        }
        // Magic 校验
        if ts_payload[0..4] != TUNNEL_MAGIC {
            return None;
        }
        // 版本校验
        if ts_payload[4] != PROTOCOL_VERSION {
            tracing::warn!(version = ts_payload[4], "不支持的隧道协议版本");
            return None;
        }
        // Type 解析
        let ftype = FrameType::from_byte(ts_payload[5])?;
        // Session ID
        let session_id = u16::from_be_bytes([ts_payload[6], ts_payload[7]]);
        // Payload 长度
        let payload_len = u16::from_be_bytes([ts_payload[8], ts_payload[9]]) as usize;
        if payload_len > ts_payload.len() - FRAME_HEADER_LEN {
            tracing::warn!(payload_len, available = ts_payload.len() - FRAME_HEADER_LEN, "帧长度超界");
            return None;
        }
        // 序号
        let seq = u32::from_be_bytes([ts_payload[10], ts_payload[11], ts_payload[12], ts_payload[13]]);
        // 标志位
        let flags = ts_payload[14];
        // payload
        let payload = ts_payload[FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload_len].to_vec();

        // 序号连续性检测（best-effort 模式丢包时告警）
        if self.have_seq && seq != self.last_seq.wrapping_add(1) {
            // 允许少量乱序（SRT 层已重排序，这里主要检测大跳变）
            let gap = seq.wrapping_sub(self.last_seq);
            if gap > 1 && gap < 100 {
                tracing::debug!(from = self.last_seq, to = seq, "帧序号跳变（可能丢帧）");
            }
        }
        self.last_seq = seq;
        self.have_seq = true;

        Some(Frame {
            ftype,
            session_id,
            seq,
            flags,
            payload,
        })
    }
}

/// 会话发送队列（每会话一个，公平调度用）
/// P1 简单实现：VecDeque 缓冲 + 统计；窗口流控信号经 ACK 帧交互
/// （P1 后半段接入流控时启用）
#[allow(dead_code)]
pub struct SessionQueue {
    /// 待发送数据（已按会话 ID 路由的分片）
    pub pending: std::collections::VecDeque<Vec<u8>>,
    /// 窗口大小（对端 ACK 更新）
    pub window: u16,
}

impl SessionQueue {
    /// 创建会话队列
    /// （P1 后半段接入流控时启用）
    #[allow(dead_code)]
    pub fn new(window: u16) -> Self {
        Self {
            pending: std::collections::VecDeque::new(),
            window,
        }
    }
}

/// 解析 SRT 消息 → 复用层帧
///
/// 2026-08-19：移除 TS 伪装层后，SRT 消息直接承载隧道帧（帧头 15B + payload），
/// 不再需要解 TS 壳，直接交给 MuxDecoder 解析帧头。
pub fn decode_srt_message(msg: &[u8], mux: &mut MuxDecoder) -> Option<Frame> {
    mux.decode_frame(msg)
}

/// 字节序辅助（调试/测试）
/// （P1 后半段接入流控时启用）
#[allow(dead_code)]
pub fn write_u16_be(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// 统计信息（会话级）
/// （P1 后半段接入指标上报时启用）
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    /// 发送帧数
    pub tx_frames: u64,
    /// 接收帧数
    pub rx_frames: u64,
    /// 发送字节
    pub tx_bytes: u64,
    /// 接收字节
    pub rx_bytes: u64,
    /// 当前缓冲（字节）
    pub buffered: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let enc = MuxEncoder::new(true);
        let mut dec = MuxDecoder::new();

        // 编码数据帧 → 直接解码（无 TS 壳，SRT 消息直接承载隧道帧）
        let frame = enc.encode_frame(FrameType::Data, 42, 0, b"hello tunnel");
        assert!(frame.len() <= FRAME_DATA_MAX + FRAME_HEADER_LEN, "帧长不得超过 SRT payload");
        let out = dec.decode_frame(&frame).unwrap();
        assert_eq!(out.ftype, FrameType::Data);
        assert_eq!(out.session_id, 42);
        assert_eq!(out.payload, b"hello tunnel");
        assert!(out.flags & FLAG_RELIABLE != 0, "可靠模式应带 RELIABLE 标志");
    }

    #[test]
    fn test_best_effort_flag() {
        let enc = MuxEncoder::new(false);
        let frame = enc.encode_frame(FrameType::Data, 1, 0, b"x");
        assert_eq!(frame[14] & FLAG_RELIABLE, 0, "尽力而为模式不带 RELIABLE 标志");
    }

    #[test]
    fn test_invalid_magic() {
        let mut dec = MuxDecoder::new();
        let bad = vec![0x00; 184];
        assert!(dec.decode_frame(&bad).is_none());
    }

    #[test]
    fn test_heartbeat_frame() {
        let enc = MuxEncoder::new(true);
        let mut dec = MuxDecoder::new();
        let frame = enc.encode_heartbeat();
        let out = dec.decode_frame(&frame).unwrap();
        assert_eq!(out.ftype, FrameType::Heartbeat);
        assert_eq!(out.session_id, 0);
        assert_eq!(out.payload.len(), 8, "心跳携带 8 字节时间戳");
    }

    #[test]
    /// M8 修复验证：心跳载荷时间戳可解析（pong RTT 计算的前置条件）
    fn test_heartbeat_timestamp_parse() {
        let enc = MuxEncoder::new(true);
        let mut dec = MuxDecoder::new();
        let frame = enc.encode_heartbeat();
        let out = dec.decode_frame(&frame).unwrap();
        let ts = heartbeat_timestamp(&out.payload).expect("8 字节载荷应解析出时间戳");
        // 时间戳应为近期时间（now ± 5s 容差）
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        assert!((now_ms - ts).abs() < 5000, "时间戳偏离当前时间过大: {ts}");
        // 非法载荷（长度不是 8）返回 None
        assert!(heartbeat_timestamp(&[1, 2, 3]).is_none());
    }
}
