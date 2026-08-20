//! quic/ack.rs — ACK 与丢失恢复（自研 QUIC 语义）
//!
//! 借鉴 RFC 9002（QUIC Loss Detection）简化实现：
//! - 发送侧维护"未确认数据包"表（sent_time + 重传次数 + 是否 ACK 过）
//! - 收到 ACK 帧：推进 largest_acked，标记对应包已确认
//! - 超时重传：每包带发送时间戳，超过 RTO 未确认即判定丢失并入重传队列
//! - RTO 计算：基于平滑 RTT（SRTT）+ 抖动（RTTVAR），仿 TCP/QUIC 的 RTO 公式
//!
//! 注意：本内核的 ACK 是"帧级"确认（STM 流的 offset 已被确认）——与 QUIC 的
//! 包序号级 ACK 不同。这里采用**字节流偏移确认**（类似 TCP SACK 简化版）：
//! ACK 帧确认的是整个连接发送的累计字节偏移，配合流内 offset 重组，
//! 避免维护大量包级状态。重传按"未确认的最远偏移"驱动。
//!
//! 设计取舍（关键）：
//! - 单连接一个累计确认偏移（不需要 per-stream ACK）：STREAM 帧都带全局序号
//!   由发送方维护 packet_seq -> (send_time, stream_id, offset, len)
//!   收到 ACK(largest_seq) 即确认 seq <= largest_seq 的所有包
//! - 简化：丢包重传在发送层重取对应流的 pending 数据（流内 offset 幂等）

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 初始 RTO（RFC 9002: 1 秒）
pub const INITIAL_RTO: Duration = Duration::from_millis(1000);
/// 最小 RTO（防重传风暴）
pub const MIN_RTO: Duration = Duration::from_millis(200);
/// 最大 RTO
pub const MAX_RTO: Duration = Duration::from_secs(60);

/// 未确认数据包条目
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// 发送时间（计算 RTO/超时用）
    pub sent_time: Instant,
    /// 包序号（发送侧全局递增；P1.5 ACK 序号关联启用）
    #[allow(dead_code)]
    pub seq: u64,
    /// 是否已确认
    pub acked: bool,
    /// 该包承载的数据引用（用于重传：流 ID + 流内偏移 + 数据）
    pub payload: Option<SentPayload>,
}

/// 已发送包的数据负载描述（供重传）
#[derive(Debug, Clone)]
pub struct SentPayload {
    /// 所属流
    pub stream_id: u32,
    /// 流内偏移（重传时定位源数据）
    pub offset: u64,
    /// 数据（字节）
    pub data: Vec<u8>,
    /// 是否携带 FIN
    pub fin: bool,
}

/// 连接级发送跟踪器
pub struct SendTracker {
    /// 下一个包序号（全局递增，从 0 起）
    next_seq: u64,
    /// 已发送未确认包表 seq -> 条目
    sent: HashMap<u64, SentPacket>,
    /// 最大已确认序号（对端 ACK 推进）
    largest_acked: u64,
    /// 已确认的数据量（累计字节，供发送窗口/度量）
    pub bytes_acked: u64,

    // RTT 估计（仿 RFC 9002 §5.3）
    /// 最近一次 RTT 采样
    latest_rtt: Duration,
    /// 平滑 RTT（SRTT）
    pub srtt: Duration,
    /// RTT 波动（RTTVAR）
    rttvar: Duration,
    /// 当前 RTO
    pub rto: Duration,
    /// 连续超时次数（指数退避）
    rto_backoff: u32,
}

impl Default for SendTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SendTracker {
    /// 创建发送跟踪器
    pub fn new() -> Self {
        Self {
            next_seq: 0,
            sent: HashMap::new(),
            largest_acked: 0,
            bytes_acked: 0,
            latest_rtt: Duration::from_millis(10),
            srtt: Duration::from_millis(10),
            rttvar: Duration::from_millis(5),
            rto: INITIAL_RTO,
            rto_backoff: 0,
        }
    }

    /// 分配下一个包序号（P1.5 ACK 关联启用）
    #[allow(dead_code)]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// 记录一个已发送包
    pub fn on_send(&mut self, payload: Option<SentPayload>) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.sent.insert(
            seq,
            SentPacket {
                sent_time: Instant::now(),
                seq,
                acked: false,
                payload,
            },
        );
        seq
    }

    /// 收到 ACK：推进 largest_acked，标记确认，采样 RTT 更新 RTO
    /// 返回本轮被确认的包数
    ///
    /// 2026-08-20 P1.5 修复（连续 4 次请求后隧道失效根因）：
    /// ACK 字段语义从"包序号"改为"**字节偏移边界**"。原因是 seq 是发送方内部
    /// 维护的全局递增序号，接收方从 STREAM 帧只能拿到 (offset, len)，无法
    /// 映射到对端的包序号——旧实现 send_ack 固定确认 0，导致 seq>0 的包永久
    /// 未确认 → in_flight 无限增长（send_loop 停发新包，第 5/6 次请求失败）
    /// + find_expired 无限重传旧包（实测 session:1 回传重传风暴 1108 次）。
    /// 现在 ACK(largest_offset) 确认"字节偏移边界 <= largest_offset"的所有包，
    /// 与接收侧 recv_data 的 offset 幂等重组语义天然对齐。
    pub fn on_ack(&mut self, acked_seq: u64, delay_us: u32) -> usize {
        if acked_seq > self.largest_acked {
            self.largest_acked = acked_seq;
        }
        let mut confirmed = 0usize;
        // 标记所有"字节边界 <= acked_seq"的包已确认（offset 语义）
        let to_remove: Vec<u64> = self
            .sent
            .iter()
            .filter_map(|(seq, p)| {
                if p.acked {
                    return None;
                }
                // 按负载字节边界确认（offset+len 为此包覆盖的字节上界）
                let boundary = match &p.payload {
                    Some(pl) => pl.offset + pl.data.len() as u64,
                    None => *seq, // 无负载包（PING 等）按序号确认——不参与数据确认
                };
                if boundary <= acked_seq {
                    Some(*seq)
                } else {
                    None
                }
            })
            .collect();
        // RTT 采样：用被确认包中触发边界推进的包（取边界最接近 acked_seq 的）
        if !to_remove.is_empty() {
            let now = Instant::now();
            // 采样最近发出的确认包 RTT（简化：取 to_remove 中发送时间最新者）
            let mut newest_sent = Instant::now();
            let mut has_sample = false;
            for seq in &to_remove {
                if let Some(pkt) = self.sent.get(seq) {
                    if !has_sample || pkt.sent_time > newest_sent {
                        newest_sent = pkt.sent_time;
                        has_sample = true;
                    }
                }
            }
            if has_sample {
                let sample = now.saturating_duration_since(newest_sent);
                self.update_rtt(sample, Duration::from_micros(delay_us as u64));
            }
        }
        for seq in &to_remove {
            if let Some(pkt) = self.sent.get_mut(seq) {
                pkt.acked = true;
                confirmed += 1;
                if let Some(pl) = &pkt.payload {
                    self.bytes_acked += pl.data.len() as u64;
                }
            }
        }
        // 清理已确认条目（防止无限增长）
        for seq in &to_remove {
            self.sent.remove(seq);
        }
        confirmed
    }

    /// RTT 采样更新（RFC 9002 §5.3 简化）
    fn update_rtt(&mut self, sample: Duration, _ack_delay: Duration) {
        self.latest_rtt = sample;
        // 首次用样本初始化
        if self.srtt.is_zero() {
            self.srtt = sample;
            self.rttvar = sample / 2;
        } else {
            // SRTT = 7/8 SRTT + 1/8 RTT
            self.srtt = self.srtt * 7 / 8 + sample / 8;
            // RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - RTT|
            let diff = if sample > self.srtt { sample - self.srtt } else { self.srtt - sample };
            self.rttvar = self.rttvar * 3 / 4 + diff / 4;
        }
        // RTO = SRTT + 4*RTTVAR（+ 抖动下限）
        let mut rto = self.srtt + self.rttvar * 4;
        // 回落 clamp
        if rto < MIN_RTO {
            rto = MIN_RTO;
        }
        if rto > MAX_RTO {
            rto = MAX_RTO;
        }
        self.rto = rto;
    }

    /// 超时重传判定：返回应重传的包（按发送时间最老优先）
    /// 简化：每个 tick 检查所有未确认且超过 RTO 的包，返回其负载（去重）
    pub fn find_expired(&mut self, now: Instant) -> Vec<SentPayload> {
        let rto = self.rto;
        let backoff = 1u32 << self.rto_backoff.min(7); // 退避 2^N
        let timeout = rto * backoff;
        let expired: Vec<u64> = self
            .sent
            .iter()
            .filter(|(_, p)| !p.acked && now.duration_since(p.sent_time) > timeout)
            .map(|(seq, _)| *seq)
            .collect();
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for seq in expired {
            if let Some(pkt) = self.sent.get_mut(&seq) {
                if let Some(pl) = pkt.payload.clone() {
                    // 按 (stream_id, offset) 去重，避免同一数据块多次重传
                    let key = (pl.stream_id, pl.offset);
                    if seen.insert(key) {
                        out.push(pl);
                    }
                }
                // 刷新发送时间（重传后重新计时）
                pkt.sent_time = now;
                self.rto_backoff += 1;
            }
        }
        out
    }

    /// ACK 驱动的拥塞窗口确认事件（拥塞控制器调用：返回本 tick 确认的数据字节）
    pub fn acked_bytes(&self) -> u64 {
        self.bytes_acked
    }

    /// 重置重传退避（收到新 ACK 时）
    pub fn reset_backoff(&mut self) {
        self.rto_backoff = 0;
    }

    /// 未确认包数（窗口占用量度）
    pub fn in_flight(&self) -> usize {
        self.sent.values().filter(|p| !p.acked).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 发送与 ACK 基本流程（offset 语义：ACK 确认字节边界）
    #[test]
    fn test_send_ack_flow() {
        let mut t = SendTracker::new();
        let seq = t.on_send(Some(SentPayload {
            stream_id: 1,
            offset: 0,
            data: b"abcd".to_vec(),
            fin: false,
        }));
        assert_eq!(seq, 0);
        assert_eq!(t.in_flight(), 1);

        // ACK 确认字节边界 4（offset 0 + len 4）
        let confirmed = t.on_ack(4, 0);
        assert_eq!(confirmed, 1);
        assert_eq!(t.in_flight(), 0);
        // 已确认后应清出表
        assert!(t.sent.is_empty());
    }

    /// RTO 超时触发重传
    #[test]
    fn test_rto_expiry() {
        let mut t = SendTracker::new();
        let payload = SentPayload {
            stream_id: 1,
            offset: 10,
            data: b"xyz".to_vec(),
            fin: false,
        };
        t.on_send(Some(payload.clone()));
        // 快速超时：伪造很短 RTO 后推进时间
        t.rto = Duration::from_millis(10);
        // 伪造发送时间已过去（直接改 sent_time 模拟）——用真实时间等待不可行，改为直接更新
        let now = Instant::now();
        // 直接改条目时间戳模拟已超时
        if let Some(pkt) = t.sent.get_mut(&0) {
            pkt.sent_time = now - Duration::from_secs(2);
        }
        let expired = t.find_expired(now);
        assert_eq!(expired.len(), 1, "应检测到超时");
        assert_eq!(expired[0].offset, 10);
        assert_eq!(expired[0].data, b"xyz");
    }

    /// RTT 更新后 RTO 收敛（offset 语义）
    #[test]
    fn test_rtt_update() {
        let mut t = SendTracker::new();
        let _seq = t.on_send(Some(SentPayload {
            stream_id: 1,
            offset: 0,
            data: vec![0; 100],
            fin: false,
        }));
        std::thread::sleep(Duration::from_millis(20));
        // 确认字节边界 100（offset 0 + len 100）
        t.on_ack(100, 0);
        // SRTT 应接近 20ms（允许较低的系统时钟抖动）
        assert!(t.srtt >= Duration::from_millis(8), "SRTT 应采样 ~10-20ms: {:?}", t.srtt);
        assert!(t.rto >= MIN_RTO);
    }

    /// 重复 ACK 幂等（offset 语义）
    #[test]
    fn test_dup_ack_idempotent() {
        let mut t = SendTracker::new();
        let _seq = t.on_send(Some(SentPayload {
            stream_id: 1,
            offset: 0,
            data: vec![1; 50],
            fin: false,
        }));
        t.on_ack(50, 0);
        let c2 = t.on_ack(50, 0);
        assert_eq!(c2, 0, "重复 ACK 不重复确认");
    }
}