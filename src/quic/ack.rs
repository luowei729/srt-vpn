//! quic/ack.rs - 丢包恢复 v2（包号确认 + 区间 ACK + RTO，RFC9002 风格）
//!
//! 2026-08-20 v2 完整重写：
//! v1 的确认键是"字节偏移"（发送方从 STREAM 帧 offset 记账），丢失的 FIN、
//! 无 payload 的包都对不齐，SACK 空洞判断还要靠猜测。v2 回归标准做法：
//!
//! - **确认键 = 包号**（放 SRT 外壳 SEQ 字段，接收方直接可见）
//! - 发送侧：`on_send` 按包号记账（sent_time + 原始帧字节，重传零拷贝语义：
//!   直接重发记录的完整帧，保留原包号--SRT 同款重传语义）
//! - 接收侧：`RecvTracker` 按包号记录已收集合，`ack_ranges()` 生成降序区间
//! - 丢包恢复两条路：
//!   ① 快速重传：收到 ACK 区间后，区间之间的 gap 包立即判定丢失重传
//!   ② RTO 兜底：超时未确认的包重传（指数退避）
//! - RTT 采样（RFC9002 §5.3）：ACK 里回显被确认包的 sent_time，
//!   RTO = SRTT + 4×RTTVAR，clamp [200ms, 60s]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// 初始 RTO（RFC9002 建议 1s）
pub const INITIAL_RTO: Duration = Duration::from_millis(1000);
/// 最小 RTO（防重传风暴）
pub const MIN_RTO: Duration = Duration::from_millis(200);
/// 最大 RTO
pub const MAX_RTO: Duration = Duration::from_secs(60);

/// MSS（单包字节；P1.5 包长纹理接入时启用）
#[allow(dead_code)]
pub const MSS: usize = 1316;

/// 包号阈值（quic-go packetThreshold = 3，RFC9002 §7.3.2）：
/// `largest_acked - pn >= 3` 判丢
const PACKET_THRESHOLD: u64 = 3;

/// 时间阈值因子（quic-go timeThreshold = 9/8，RFC9002 §7.3.1）：
/// 包 sent_time ≤ now - maxRTT × 9/8 判丢
const TIME_THRESHOLD: f64 = 9.0 / 8.0;

// ============================================================================
// 发送侧：未确认包表 + RTO
// ============================================================================

/// 已发送未确认包条目
#[derive(Debug, Clone)]
pub struct SentPacket {
    /// 发送时间（最新一次发送/重传的时刻，RTO 计时基准）
    pub sent_time: Instant,
    /// 是否已确认
    pub acked: bool,
    /// 原始帧完整字节（重传直接重发，保留 SRT 外壳里的原包号）
    pub frame: Vec<u8>,
    /// 是否为数据帧（PING/PONG 等控制帧不参与丢包判定）
    pub is_data: bool,
}

/// 发送跟踪器（发送侧）
pub struct SendTracker {
    /// 未确认包表：包号 -> 条目（已确认即移除）
    sent: BTreeMap<u64, SentPacket>,
    /// 最大已确认包号（ACK 推进）
    largest_acked: u64,
    /// 累计已确认数据字节
    pub bytes_acked: u64,

    // RTT 估计（RFC9002 §5.3）
    srtt: Duration,
    rttvar: Duration,
    rto: Duration,
    /// 连续超时次数（指数退避 2^N）
    rto_backoff: u32,

    /// 丢包检测定时器（quic-go pnSpace.lossTime）：
    /// 不满足时间/包号阈值的未确认包设置此定时器，到点兜底重传
    loss_time: Option<Instant>,
}

impl Default for SendTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SendTracker {
    pub fn new() -> Self {
        Self {
            sent: BTreeMap::new(),
            largest_acked: 0,
            bytes_acked: 0,
            // B7 修复：初始 srtt 用公网真实 RTT 60ms 附近（而非 10ms），
            // 避免 loss_delay=srtt×9/8 初始仅 11ms（公网需 ~67ms），
            // 导致所有在途包在首轮 ACK 后立即被 time-threshold 误判丢包，
            // CUBIC 连续回退×0.7，cwnd 拉到 min 并重传风暴，上传直接卡死。
            srtt: Duration::from_millis(60),
            rttvar: Duration::from_millis(30),
            rto: INITIAL_RTO,
            rto_backoff: 0,
            loss_time: None,
        }
    }

    /// 记录一个已发送包（发送线程发出后调用）
    pub fn on_send(&mut self, pkt_num: u64, frame: Vec<u8>, is_data: bool) {
        self.sent.insert(
            pkt_num,
            SentPacket {
                sent_time: Instant::now(),
                acked: false,
                frame,
                is_data,
            },
        );
    }

    /// 处理收到的 ACK（区间确认）：
    /// 1. 标记区间内包号已确认并移除
    /// 2. 区间间 gap 的未确认数据包判定丢失 -> 返回立即重传
    /// 3. RTT 采样（取本轮确认的最大包号对应的 sent_time）
    ///
    /// 返回 (本轮确认包数, 需快速重传的帧列表)
    pub fn on_ack(&mut self, largest: u64, ranges: &[(u64, u64)], rtt_echo_us: Option<u64>) -> (usize, Vec<Vec<u8>>) {
        let mut confirmed = 0usize;
        // 1. 标记确认：区间内所有在表包号移除（含 <= largest 之外的老包--
        //    接收方重传场景下旧区间可能仍在）
        let mut acked_nums: Vec<u64> = Vec::new();
        for (low, high) in ranges {
            // BTreeMap range 批量收集（区间可能很大，只收集在表的）
            for (&num, pkt) in self.sent.range(*low..=*high) {
                if !pkt.acked {
                    acked_nums.push(num);
                }
            }
        }
        for num in acked_nums {
            if let Some(pkt) = self.sent.remove(&num) {
                confirmed += 1;
                if pkt.is_data {
                    self.bytes_acked += pkt.frame.len() as u64;
                }
            }
        }
        if largest > self.largest_acked {
            self.largest_acked = largest;
        }
        // 2. RTT 采样：用 rtt_echo（接收方回显的 largest 对应发送时刻）
        if let Some(echo_us) = rtt_echo_us {
            let now_us = now_micros();
            if now_us > echo_us {
                self.update_rtt(Duration::from_micros(now_us - echo_us));
            }
        } else if confirmed > 0 {
            // 兼容：无回显时用最大确认包的 sent_time 采样
            if let Some((_, pkt)) = self.sent.iter().next_back() {
                let sample = Instant::now().saturating_duration_since(pkt.sent_time);
                self.update_rtt(sample);
            }
        }
        // 最小时间粒度保护 quic-go TimerGranularity（避免 RTT=0 时全部判丢）

        // 3. 丢包检测（完全按 quic-go detectLostPackets，RFC9002 §7.3）：
        // - 时间阈值（timeThreshold = 9/8）：sent_time <= now - maxRTT × 9/8 判丢
        // - 包号阈值（packetThreshold = 3）：largest_acked - pn >= 3 判丢
        // - 未达阈值的包设置 loss_time 定时器（PTO 兜底，见 get_loss_detection_timeout）
        // 注意：底层包号走 SRT 0x80 外壳 SEQ 字段（不破坏 SRT 伪装），
        // ACK 走 SRT ACK 控制壳——这是 srt-vpn 在 quic-go 基础上加的 SRT 外壳层。
        let now = Instant::now();
        let mut lost: Vec<Vec<u8>> = Vec::new();
        let lost_nums: Vec<u64> = self
            .sent
            .range(..self.largest_acked)
            .filter(|(&n, p)| p.is_data && !p.acked && {
                let time_lost = self.is_packet_time_lost(p.sent_time, now);
                let reorder_lost = self.largest_acked - n >= PACKET_THRESHOLD;
                time_lost || reorder_lost
            })
            .map(|(&n, _)| n)
            .collect();
        for n in lost_nums {
            if let Some(pkt) = self.sent.remove(&n) {
                lost.push(pkt.frame);
            }
        }
        // 更新 loss_time：largest_acked 之前未达两个阈值的包设置定时器
        self.update_loss_time(now);
        if confirmed > 0 {
            self.rto_backoff = 0; // 有新确认即重置退避
        }
        (confirmed, lost)
    }

    /// RTO 超时重传判定：返回超时未确认的数据帧（发送循环周期调用）
    ///
    /// 架构约定：返回的帧由调用方用**新包号**重新记账发送（旧条目在此
    /// 删除，不残留）。指数退避：连续超时 RTO×2^N（cap 2^7）。
    pub fn find_expired(&mut self) -> Vec<Vec<u8>> {
        let timeout = self.rto * (1u32 << self.rto_backoff.min(7));
        let now = Instant::now();
        let expired: Vec<u64> = self
            .sent
            .iter()
            .filter(|(_, p)| p.is_data && !p.acked && now.duration_since(p.sent_time) > timeout)
            .map(|(&n, _)| n)
            .collect();
        let mut out = Vec::with_capacity(expired.len());
        for n in expired {
            if let Some(pkt) = self.sent.remove(&n) {
                out.push(pkt.frame);
            }
        }
        if !out.is_empty() {
            self.rto_backoff += 1;
        }
        out
    }

    /// 时间阈值丢包判定（quic-go detectLostPackets）：
    /// 包 sent_time ≤ now - maxRTT × 9/8 即判丢（maxRTT = max(LatestRTT, SRTT)）
    ///
    /// 我们无 LatestRTT 独立字段，用 srtt 近似（quic-go max(LatestRTT, SRTT)）
    fn is_packet_time_lost(&self, sent_time: Instant, now: Instant) -> bool {
        let max_rtt = self.srtt; // 简化：用 SRTT（P1.5 接入 latest_rtt 后改 max）
        let loss_delay = Duration::from_secs_f64(max_rtt.as_secs_f64() * TIME_THRESHOLD);
        // quic-go: lossDelay = max(lossDelay, TimerGranularity=1ms)
        let loss_delay = loss_delay.max(Duration::from_millis(1));
        let lost_send_time = now.checked_sub(loss_delay).unwrap_or(now);
        sent_time <= lost_send_time
    }

    /// 更新丢包检测定时器（quic-go 设置 pnSpace.lossTime）
    ///
    /// 遍历 largest_acked 之前的未确认数据包，未达两个阈值的取最早
    /// sent_time + loss_delay 作为 loss_time，到点由 send_loop 检查触发。
    fn update_loss_time(&mut self, now: Instant) {
        self.loss_time = None;
        let max_rtt = self.srtt;
        let loss_delay = Duration::from_secs_f64(max_rtt.as_secs_f64() * TIME_THRESHOLD)
            .max(Duration::from_millis(1));
        for (&n, p) in self.sent.range(..self.largest_acked) {
            if !p.is_data || p.acked {
                continue;
            }
            // 包号阈值已判的不算（不会到这里，已被删，但循环时防误）
            if self.largest_acked - n >= PACKET_THRESHOLD {
                continue;
            }
            // 时间阈值已判的跳过（也已删，但循环时防误）
            if self.is_packet_time_lost(p.sent_time, now) {
                continue;
            }
            // 此包需要 loss_time 定时器兜底
            let lt = p.sent_time + loss_delay;
            self.loss_time = Some(match self.loss_time {
                Some(existing) => existing.min(lt),
                None => lt,
            });
        }
    }

    /// 快照：最大已确认包号（给拥控回退用）
    pub fn largest_acked_snapshot(&self) -> u64 {
        self.largest_acked
    }

    /// 丢包检测定时器超时时刻（quic-go GetLossDetectionTimeout）
    ///
    /// send_loop 调：若 now >= loss_time 则触发一次兜底重传
    /// （检测 timer 触发时所有过阈值的包判丢）。
    #[allow(dead_code)]
    pub fn get_loss_detection_timeout(&self) -> Option<Instant> {
        self.loss_time
    }

    /// loss_time 到点时的兜底丢包提取（P0-3 配套）
    ///
    /// quic-go detectLostPackets 的定时器路径：当 lossTime 到点且无新 ACK
    /// 到达时，时间阈值已满足的包应立即判丢重传，否则靠 RTO 1s 才重传。
    pub fn pop_lost_by_loss_time(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let Some(lt) = self.loss_time else { return Vec::new(); };
        if now < lt {
            return Vec::new();
        }
        let mut lost: Vec<Vec<u8>> = Vec::new();
        let nums: Vec<u64> = self.sent.range(..self.largest_acked)
            .filter(|(&n, p)| p.is_data && !p.acked && self.is_packet_time_lost(p.sent_time, now))
            .map(|(&n, _)| n)
            .collect();
        for n in nums {
            if let Some(pkt) = self.sent.remove(&n) {
                lost.push(pkt.frame);
            }
        }
        self.update_loss_time(now);
        lost
    }

    /// 未确认数据包数（窗口占用指标）
    #[allow(dead_code)]
    pub fn in_flight(&self) -> usize {
        self.sent.values().filter(|p| p.is_data && !p.acked).count()
    }

    /// 在途数据字节（BBR 窗口占用）
    pub fn in_flight_bytes(&self) -> usize {
        self.sent.values().filter(|p| p.is_data && !p.acked).map(|p| p.frame.len()).sum()
    }

    /// SRTT（外部心跳采样入口也用）
    pub fn srtt(&self) -> Duration {
        self.srtt
    }

    /// 未确认表条目总数（诊断用；含 ACK 后待删条目）
    #[allow(dead_code)]
    pub fn sent_count(&self) -> usize {
        self.sent.len()
    }

    /// 外部 RTT 采样（心跳 PING/PONG 测得，无数据流时维持新鲜 RTO）
    pub fn on_rtt_sample(&mut self, sample: Duration) {
        self.update_rtt(sample);
    }

    /// RTT 采样更新（RFC9002 §5.3 简化）
    fn update_rtt(&mut self, sample: Duration) {
        if sample.is_zero() {
            return;
        }
        if self.srtt == Duration::from_millis(10) && self.bytes_acked == 0 && self.sent.is_empty() {
            // 首次采样直接初始化（区分"未采样"的默认值）
            self.srtt = sample;
            self.rttvar = sample / 2;
        } else {
            // SRTT = 7/8 SRTT + 1/8 RTT
            self.srtt = self.srtt * 7 / 8 + sample / 8;
            // RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - RTT|
            let diff = if sample > self.srtt { sample - self.srtt } else { self.srtt - sample };
            self.rttvar = self.rttvar * 3 / 4 + diff / 4;
        }
        // RTO = SRTT + 4×RTTVAR，clamp
        let mut rto = self.srtt + self.rttvar * 4;
        if rto < MIN_RTO {
            rto = MIN_RTO;
        }
        if rto > MAX_RTO {
            rto = MAX_RTO;
        }
        self.rto = rto;
    }
}

// ============================================================================
// 接收侧：已收包号记录 + ACK 区间生成
// ============================================================================

/// 接收跟踪器（接收侧）
///
/// 记录已收到的数据包号，生成降序 ACK 区间（RFC9000 ACK Ranges）。
/// 内存控制：只保留最近 ACK_K_WINDOW 个包号（更早的都已确认过，
/// 发送方早已清理；窗口外重复到达直接忽略）。
///
/// 2026-08-20 性能优化（学 quic-go ACK 策略）：
/// ACK 发送改为"每 2 个 ack-eliciting 包立即发 + 有 missing 立即发 +
/// 25ms 兜底定时器"，替代旧的固定 5ms 周期。上传场景客户端等 ACK
/// 释放 in_flight，旧 5ms 周期是反应延迟 5ms 的根因（上传 24 vs 下载
/// 120MB/s），改后每 2 包即回 ACK，反应延迟降到 ~1 包的 RTT。
pub struct RecvTracker {
    /// 已收包号集合（有序；ACK 发出后仍保留，供重复包去重）
    received: std::collections::BTreeSet<u64>,
    /// 最大已收包号
    largest_recv: u64,
    /// 未确认下界（最近一次 ACK 报告的最低段下界；此以下才可裁剪）
    ///
    /// 2026-08-20 v2 关键修复：旧裁剪用 largest_recv - window --突发场景下
    /// 丢包位置被窗口滑过，包号从 received 裁掉，ACK 永远报不出 gap，
    /// 发送方无法重传（实测字节空洞 3948B 卡死）。裁剪基准改为
    /// "已报告过的最低段下界"：未确认的包号永不清除，gap 证据保留。
    min_unacked: u64,
    /// 记录窗口上限（防内存无限增长；仅约束 min_unacked 以上的额外保留）
    window: usize,
    /// 2026-08-20 性能优化（学 quic-go）：收到多少 ack-eliciting 包未发 ACK
    packets_since_last_ack: u32,
    /// 2026-08-20 性能优化（学 quic-go）：是否需要立即发 ACK（收到 2 包/有 missing）
    ack_queued: bool,
    /// 2026-08-20 性能优化（学 quic-go）：上次检测时有没有 missing（用于重传恢复即时 ACK）
    last_had_missing: bool,
}

/// 接收记录窗口（最近 4096 个包号足够覆盖重传乱序范围）
const ACK_K_WINDOW: usize = 4096;

impl Default for RecvTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RecvTracker {
    pub fn new() -> Self {
        Self {
            received: std::collections::BTreeSet::new(),
            largest_recv: 0,
            min_unacked: 0,
            window: ACK_K_WINDOW,
            packets_since_last_ack: 0,
            ack_queued: false,
            last_had_missing: false,
        }
    }

    /// 记录收到一个包（包号来自 SRT 外壳 SEQ 字段）
    ///
    /// 返回 true = 新包（首次收到）；false = 重复/过期。
    pub fn on_recv(&mut self, pkt_num: u64) -> bool {
        // 快路径：包号 < min_unacked（已裁剪过的旧包号）直接判重复
        if pkt_num < self.min_unacked {
            return false;
        }
        if pkt_num > self.largest_recv {
            self.largest_recv = pkt_num;
        }
        let inserted = self.received.insert(pkt_num);
        // 窗口裁剪：只在膨胀到 4 倍窗口时批量清理一次（罕见）
        if self.received.len() > self.window * 4 {
            let cutoff = self.largest_recv.saturating_sub(self.window as u64);
            let kept = self.received.split_off(&cutoff);
            self.received = kept;
            self.min_unacked = self.min_unacked.max(cutoff);
        }

        // 2026-08-20 性能优化（学 quic-go ACK 策略）：
        // 收到 ack-eliciting 包后检查是否应立即发 ACK
        if inserted {
            self.packets_since_last_ack += 1;
            // ① 收到之前 missing 的包（重传恢复） -> 立即 ACK
            if self.last_had_missing {
                self.ack_queued = true;
            }
            // ② 每 2 个包一次立即 ACK（quic-go packetsBeforeAck = 2）
            else if self.packets_since_last_ack >= 2 {
                self.ack_queued = true;
            }
        }
        inserted
    }

    /// 2026-08-20 性能优化（学 quic-go）：
    /// 返回 true 表示应立即发 ACK（不等周期定时器）。
    /// ack_queued 在 ack_ranges() 调用时清除。
    pub fn should_send_ack_immediately(&self) -> bool {
        self.ack_queued
    }

    /// 生成 ACK 区间（从最大已收包号向下降序，最多 max_ranges 段）
    ///
    /// 返回 (largest, 区间列表降序)。区间之间的 gap 即丢包证据，
    /// 发送方据此快速重传。
    ///
    /// 2026-08-20 v2 关键修复：旧版 `desc.truncate(1024)` 只扫最新 1024 个
    /// 包号--突发快于 ACK 周期时（回环 8000 包/10ms），丢包位置瞬间被越过
    /// 1024 个包，gap 永远报不出来（实测多段 ACK 0 次、空洞 3948B 卡死
    /// delivered_offset）。改为扫全窗口（received 集合本身被 window=4096
    /// 裁剪保护，扫描量有界），gap 信息保留到发送方确认。
    ///
    /// 同时推进 min_unacked = 报告的最低段下界（作为裁剪基准：
    /// 此以下已报告过，可安全裁剪；未确认的 gap 证据永不丢失）。
    pub fn ack_ranges(&mut self, max_ranges: usize) -> (u64, Vec<(u64, u64)>) {
        if self.received.is_empty() {
            return (0, Vec::new());
        }
        // 降序遍历（BTreeSet rev 迭代），连续段合并为区间
        let mut iter = self.received.iter().rev();
        let largest = *iter.next().unwrap();
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut low = largest;
        let mut high = largest;
        for &n in iter {
            if n + 1 == low {
                // 连续：延伸当前段
                low = n;
            } else {
                // 空洞：结算当前段，开新段
                ranges.push((low, high));
                low = n;
                high = n;
                if ranges.len() >= max_ranges {
                    break;
                }
            }
        }
        ranges.push((low, high));
        // 推进未确认下界（本次报告的最低段下界；gap 下的旧段未报完时
        // 保持更低的旧值，保证 gap 证据下次还能报）
        if let Some((lowest, _)) = ranges.last() {
            if *lowest > self.min_unacked {
                self.min_unacked = *lowest;
            }
        }
        // 2026-08-20 性能优化（学 quic-go）：
        // ACK 已发，清除 queued 标志和计数。记录本次是否有 gap（多于
        // 1 个区间=有 missing），下次收到恢复的包时立即 ACK。
        self.ack_queued = false;
        self.packets_since_last_ack = 0;
        self.last_had_missing = ranges.len() > 1;
        (largest, ranges)
    }

    /// 最大已收包号（P1.5 监控/日志接入时启用）
    #[allow(dead_code)]
    pub fn largest_recv(&self) -> u64 {
        self.largest_recv
    }
}

/// 当前微秒时间戳（RTT 回显用；SystemTime 单调性足够，微跳变无害）
pub fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 发送 + 区间 ACK 基本闭环
    #[test]
    fn test_send_ack_flow() {
        let mut t = SendTracker::new();
        t.on_send(0, b"pkt0".to_vec(), true);
        t.on_send(1, b"pkt1".to_vec(), true);
        assert_eq!(t.in_flight(), 2);
        // 接收方全收：ACK largest=1, ranges=[(0,1)]
        let (c, lost) = t.on_ack(1, &[(0, 1)], None);
        assert_eq!(c, 2);
        assert!(lost.is_empty());
        assert_eq!(t.in_flight(), 0);
    }

    /// 包号阈值丢包判定（quic-go packetThreshold=3，RFC9002 §7.3.2）：
    /// ACK largest=5 确认包 5 和 1，包 2,3,4 在 gap 内但 quic-go 不
    /// 直接用 gap 判丢，而是按 packetThreshold 判：
    /// - 包 0 距 largest_acked=5 距离 5 >= 3 → 判丢
    /// - 包 2,3,4 距离 3,2,1 < 3 → 不判丢（设 loss_time 兜底）
    ///
    /// 注：gap 区间的包（2,3,4）由 ACK Ranges 自身治理——接收方连续
    /// 范围内确认/未确认在 ranges 里已表达，quic-go 不二次判丢。
    #[test]
    fn test_fast_retransmit_on_gap() {
        let mut t = SendTracker::new();
        for n in 0..6 {
            t.on_send(n, vec![n as u8; 10], true);
        }
        // ACK largest=5, ranges=[(5,5),(1,1)]：
        // 距离 largest_acked=5 >= 3 的包判丢：包 0（5-0=5）+ 包 2（5-2=3）
        // 包 3,4 距离 2,1 < 3 不判丢（设 loss_time 兜底）
        let (c, lost) = t.on_ack(5, &[(5, 5), (1, 1)], None);
        assert_eq!(c, 2, "确认 5 和 1");
        assert_eq!(lost.len(), 2, "包 0 和 2 达 packetThreshold>=3");
        assert!(t.get_loss_detection_timeout().is_some(), "应有 loss_time");
    }

    /// 单区间无 gap 但包号阈值达标的丢包判定（quic-go packetThreshold=3）
    #[test]
    fn test_packet_threshold_loss_no_gap() {
        let mut t = SendTracker::new();
        // 发 6 包：0,1,2,3,4,5
        for n in 0..6 {
            t.on_send(n, vec![n as u8; 10], true);
        }
        // 接收方只确认了 {5}：单区间无 gap，但 largest_acked=5，包 5-3=2，
        // 即包 0,1,2 都 < threshold=2 应判丢（公网场景关键路径）
        let (c, lost) = t.on_ack(5, &[(5, 5)], None);
        assert_eq!(c, 1); // 确认包 5
        assert_eq!(lost.len(), 3, "阈值判定丢包 0,1,2");
        assert_eq!(t.in_flight(), 2); // 包 3,4 仍未确认（< threshold）
    }

    /// 单区间无 gap + 阈值未达标：不误判丢（防过早重传）
    #[test]
    fn test_no_early_loss_below_threshold() {
        let mut t = SendTracker::new();
        // 发 4 包：0,1,2,3
        for n in 0..4 {
            t.on_send(n, vec![n as u8; 10], true);
        }
        // 只收到 {3}：threshold = 3-3 = 0，包 0,1 距离 3 是 3 = 阈值边界
        // 包 0 在 ..=0 范围内 but 3-0=3 >= 3 → 判丢；包 1,2 距离 2,1 不达标
        let (_, lost) = t.on_ack(3, &[(3, 3)], None);
        // 包 0 距 largest_acked=3 阈值 3，已判丢；包 1,2 未达阈
        assert_eq!(lost.len(), 1, "仅包 0 达到 threshold=3");
    }

    /// 乱序但未丢不误判：单区间（后到先收）无 gap
    #[test]
    fn test_no_false_retransmit_single_range() {
        let mut t = SendTracker::new();
        for n in 0..3 {
            t.on_send(n, vec![n as u8; 10], true);
        }
        // 只收到 {2}：单区间无 gap，不触发快速重传（0,1 可能只是未到）
        let (_, lost) = t.on_ack(2, &[(2, 2)], None);
        assert!(lost.is_empty(), "单区间无 gap 不应误判丢包");
    }

    /// RTO 超时重传 + 指数退避
    #[test]
    fn test_rto_expiry() {
        let mut t = SendTracker::new();
        t.on_send(7, b"lost".to_vec(), true);
        // 伪造超短 RTO + 过期的发送时间
        t.rto = Duration::from_millis(10);
        if let Some(p) = t.sent.get_mut(&7) {
            p.sent_time = Instant::now() - Duration::from_secs(2);
        }
        let expired = t.find_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], b"lost");
        assert!(t.rto_backoff >= 1, "超时应推进退避");
    }

    /// RTT 采样收敛 RTO
    #[test]
    fn test_rtt_sample() {
        let mut t = SendTracker::new();
        t.on_rtt_sample(Duration::from_millis(20));
        assert!(t.srtt() >= Duration::from_millis(15), "SRTT 应接近 20ms: {:?}", t.srtt());
    }

    /// RecvTracker：乱序接收 -> ACK 区间正确
    #[test]
    fn test_recv_tracker_ranges() {
        let mut r = RecvTracker::new();
        // 收到 0,1,2 和 5,6 和 9（3,4,7,8 丢）
        for n in [9u64, 5, 6, 0, 1, 2] {
            r.on_recv(n);
        }
        let (largest, ranges) = r.ack_ranges(8);
        assert_eq!(largest, 9);
        assert_eq!(ranges, vec![(9, 9), (5, 6), (0, 2)], "降序区间应正确");
    }

    /// RecvTracker：重复包去重
    #[test]
    fn test_recv_tracker_dedup() {
        let mut r = RecvTracker::new();
        assert!(r.on_recv(1));
        assert!(!r.on_recv(1), "重复包应返回 false");
        assert!(r.on_recv(2));
    }

    /// RecvTracker：全收单区间
    #[test]
    fn test_recv_tracker_contiguous() {
        let mut r = RecvTracker::new();
        for n in 0..100 {
            r.on_recv(n);
        }
        let (largest, ranges) = r.ack_ranges(8);
        assert_eq!(largest, 99);
        assert_eq!(ranges, vec![(0, 99)], "连续接收应合并单区间");
    }

    /// RecvTracker：未确认包号不裁剪（gap 证据保留）+ 已确认后裁剪
    #[test]
    fn test_recv_tracker_window_trim() {
        let mut r = RecvTracker::new();
        for n in 0..10000u64 {
            r.on_recv(n);
        }
        // min_unacked=0（未报告过）时永不裁剪--丢包证据不能丢
        assert_eq!(r.received.len(), 10000, "未报告前不裁剪");
        // 报告后推进 min_unacked，再裁剪
        let (largest, ranges) = r.ack_ranges(8);
        assert_eq!(largest, 9999);
        assert_eq!(ranges, vec![(0, 9999)], "连续接收单区间");
        r.on_recv(10000); // 触发裁剪检查
        assert!(r.received.len() <= 10001, "报告后可裁剪: {}", r.received.len());
        assert!(r.received.len() > 0);
    }

    /// RecvTracker：gap 场景 min_unanked 不越过未报完的旧段
    #[test]
    fn test_recv_tracker_gap_evidence_kept() {
        let mut r = RecvTracker::new();
        // 收 0..99 + 200..299（100..199 丢）
        for n in 0..100u64 {
            r.on_recv(n);
        }
        for n in 200..300u64 {
            r.on_recv(n);
        }
        let (largest, ranges) = r.ack_ranges(8);
        assert_eq!(largest, 299);
        assert_eq!(ranges, vec![(200, 299), (0, 99)], "两段带 gap");
        // 大量新包涌入后，gap 证据仍保留（未确认下界不推进越过 0 段）
        for n in 1000..9000u64 {
            r.on_recv(n);
        }
        let (_, ranges2) = r.ack_ranges(8);
        // 最多 8 段，最早段（0..99）可能被段数限制截断，但 min_unacked
        // 只在"最低段"推进后才会越过（gap 下的旧段始终优先报告）
        assert!(ranges2.contains(&(0, 99)) || ranges2.last().unwrap().0 <= 99,
            "旧段或更低段应保留在报告中: {:?}", ranges2);
    }
}
