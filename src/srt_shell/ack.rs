//! srt_shell/ack.rs — SRT ACK 节奏仿真
//!
//! 伪装目标（重构共识决策 C：ACK 节奏仿真）：真 SRT/UDT 的 ACK 行为是
//! 周期性控制包（约每 10ms / 每 RTT），负载小且高频。本模块在传输层
//! ACK 之上，按 SRT 节奏向对端发送"外形 ACK"，使抓包呈现 SRT 的
//! 时序纹理（不承载实际确认语义——真实可靠性由内层 quic/ack.rs 承担）。
//!
//! 注意：这是"披上 SRT 外形的装饰性 ACK"，与真 ACK 不同。它让 DPI 从
//! 包长/时序看"像 SRT"；真正的丢包补发/窗口推进走内层 ACK 帧。

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// SRT ACK 发送间隔（约 10ms，对齐 libsrt 的 COMM_SYN_INTERVAL_US=10ms）
pub const ACK_INTERVAL: Duration = Duration::from_millis(10);

/// ACK 序号（单调递增，仿真 SRT ACK 序号纹理）
static ACK_SEQ: AtomicU32 = AtomicU32::new(1);

/// 生成一条装饰性 SRT ACK 控制包（外层 0x80 02 00 00 + 控制信息）
///
/// 控制信息布局（对齐 libsrt packet.cpp pack(UMSG_ACK)）：
/// [ACK seq u32][数据 seq 最小][RTT u32][RTT var u32][buffer left]
pub fn make_ack_packet() -> Vec<u8> {
    use crate::srt_shell::header::MSG_ACK;
    use crate::srt_shell::outer::{encode_ctrl_packet, now_ts_us};
    let seq = ACK_SEQ.fetch_add(1, Ordering::Relaxed);
    // 控制信息（简化：seq + 最小 ACK seq + RTT 0）
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&(seq - 1).to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes()); // RTT（装饰值）
    let _ = now_ts_us();
    encode_ctrl_packet(MSG_ACK, 0, &payload)
}

/// 判断是否到了发送装饰 ACK 的时刻（按 ACK_INTERVAL 节流）
pub fn should_emit_ack(last_ack_at: Instant, now: Instant) -> bool {
    now.duration_since(last_ack_at) >= ACK_INTERVAL
}

/// 心跳 keepalive（SRT 空闲时定期发包，仿真 SRT 空闲特征）
pub fn make_keepalive() -> Vec<u8> {
    use crate::srt_shell::header::MSG_NACK;
    use crate::srt_shell::outer::encode_ctrl_packet;
    // SRT keepalive 用 NACK(3) 空包（libsrt 空闲发 keep-alive 用控制包）
    // 实际 libsrt 的 keep-alive 是发送 UMSG_KEEPALIVE(6)；简化用 NACK 填充
    // 对齐 DPI 判断：保持周期性小控制包特征
    encode_ctrl_packet(MSG_NACK, 0, &[]) // 空控制包（等价 keepalive 外形）
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ACK 包外形（0x80 02 开头 + 控制信息）
    #[test]
    fn test_ack_shape() {
        let pkt = make_ack_packet();
        assert_eq!(&pkt[0..4], &[0x80, 0x02, 0, 0], "ACK 应 0x80 02 00 00");
        assert!(pkt.len() >= 16 + 12, "ACK 应含控制信息");
    }

    /// ACK 序号单调
    #[test]
    fn test_ack_seq_increasing() {
        let a = make_ack_packet();
        let b = make_ack_packet();
        let seq_a = u32::from_be_bytes([a[16], a[17], a[18], a[19]]);
        let seq_b = u32::from_be_bytes([b[16], b[17], b[18], b[19]]);
        assert_eq!(seq_b, seq_a + 1, "ACK 序号应递增");
    }

    /// 节流判断
    #[test]
    fn test_should_emit() {
        let now = Instant::now();
        assert!(should_emit_ack(now - Duration::from_secs(1), now), "超周期应发");
        assert!(!should_emit_ack(now - Duration::from_millis(1), now), "未到周期不应发");
    }
}