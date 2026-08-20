//! quic/congctl.rs — CUBIC + Hybrid Slow Start + Pacer（完全按 quic-go 设计）
//!
//! 2026-08-20 重构（完全按 quic-go `internal/congestion/{pacer.go, cubic.go,
//! cubic_sender.go, hybrid_slow_start.go}` 移植，替代 BBR v1）：
//!
//! BBR v1 病灶（2/4 连接上传卡死根因）：
//! ① ProbeRTT 重置 min_rtt=100ms 后 bdp≈0，cwnd 跌到 cwnd_min=5264，
//!   max_bw 累乘 0.7 跌到 10 字节/秒，pacer 速率 6 字节/秒（诊断实测）
//! ② 依赖带官认知（max_bw 采样），回环极低 RTT 下采样虚高不稳定
//!
//! quic-go 用 CUBIC + Hybrid Slow Start + pacer（不靠带官认知）：
//! - pacer rate = cwnd / srtt × 5/4（直接从窗口和 RTT 算，回环正确）
//! - CUBIC 丢包 ×0.7，ACK 按三次函数凸回最大点
//! - Hybrid Slow Start 用 RTT 延迟增加退出慢启动（不靠带官认知）

use std::time::{Duration, Instant};

// ============================================================================
// 常量（与 quic-go 一致）
// ============================================================================

/// 单包字节（与外壳 payload 对齐）
const MSS: usize = 1316;

/// 初始拥塞窗口 32 包（quic-go initialCongestionWindow）
const INITIAL_CWND_PACKETS: usize = 32;

/// cwnd 上限（防极低 RTT 回环 cwnd 暴涨；与 enlarge_socket_buffers 4MB 对齐）
const CWND_MAX: usize = 4 * 1024 * 1024;

/// cwnd 下限 2 包（quic-go minCongestionWindowPackets = 2）
const CWND_MIN_PACKETS: usize = 2;

/// pacer 最大突发包数（quic-go maxBurstSizePackets = 10）
const MAX_BURST_PACKETS: usize = 10;

/// CUBIC 回退因子（quic-go beta = 0.7）
const BETA: f64 = 0.7;

/// CUBIC 额外回退因子（quic-go betaLastMax = 0.85）
const BETA_LAST_MAX: f64 = 0.85;

/// pacer rate 调整因子 ×5/4（quic-go adjustedBandwidth，防 RTT 波动欠利用）
const PACING_RATE_FACTOR: f64 = 1.25;

/// CUBIC cubeScale（quic-go cubeScale = 40）
const CUBE_SCALE: u64 = 40;

/// CUBIC cubeCongestionWindowScale（quic-go cubeCongestionWindowScale = 410）
const CUBE_CWND_SCALE: u64 = 410;

/// Hybrid Slow Start 退出窗口下限 16 包（quic-go hybridStartLowWindow）
const HYBRID_LOW_WINDOW_PACKETS: usize = 16;

/// Hybrid Slow Start 最小采样数 8（quic-go hybridStartMinSamples）
const HYBRID_MIN_SAMPLES: u32 = 8;

/// Hybrid Slow Start 延迟因子指数 3（2^3=8，quic-go hybridStartDelayFactorExp）
const HYBRID_DELAY_FACTOR_EXP: u32 = 3;

/// Hybrid Slow Start 延迟阈值下限 4ms（quic-go hybridStartDelayMinThresholdUs）
const HYBRID_DELAY_MIN_US: u64 = 4000;

/// Hybrid Slow Start 延迟阈值上限 16ms（quic-go hybridStartDelayMaxThresholdUs）
const HYBRID_DELAY_MAX_US: u64 = 16000;

// ============================================================================
// Pacer 令牌桶（quic-go pacer.go）
// ============================================================================

/// pacer 令牌桶（quic-go pacer.go 移植）
///
/// rate 由外部传入（CUBIC 用 bandwidth_estimate = cwnd/srtt × 5/4），
/// pacer 不自己算 rate。
pub struct Pacer {
    /// 上次发送后的剩余预算（字节）
    budget_at_last_sent: u64,
    /// 单包字节（MSS）
    max_datagram_size: usize,
    /// 上次发送时刻
    last_sent_time: Instant,
    /// 是否已初始化（首次 send 前用 maxBurst，避免 cold start 卡死）
    initialized: bool,
    /// 当前带宽估计（字节/秒；由 CubicSender.bandwidth_estimate 更新）
    bandwidth: u64,
}

impl Pacer {
    pub fn new() -> Self {
        Self {
            budget_at_last_sent: 0,
            max_datagram_size: MSS,
            last_sent_time: Instant::now(),
            initialized: false,
            bandwidth: 0,
        }
    }

    /// 更新带宽估计（由 CubicSender 在 pacer 操作前调用）
    pub fn set_bandwidth(&mut self, bw: u64) {
        self.bandwidth = bw;
    }

    /// 记录发出一个包（quic-go pacer.SentPacket）
    pub fn sent_packet(&mut self, send_time: Instant, size: usize) {
        self.initialized = true;
        let budget = self.budget(send_time);
        self.budget_at_last_sent = budget.saturating_sub(size as u64);
        self.last_sent_time = send_time;
    }

    /// 当前可用预算（quic-go pacer.Budget）
    ///
    /// budget_at_last_sent + rate × delta，上限 maxBurst。
    pub fn budget(&self, now: Instant) -> u64 {
        if !self.initialized {
            return self.max_burst_size();
        }
        if self.bandwidth == 0 {
            return self.max_burst_size();
        }
        let delta = now.saturating_duration_since(self.last_sent_time).as_secs_f64();
        let added = (self.bandwidth as f64 * delta) as u64;
        self.budget_at_last_sent.saturating_add(added).min(self.max_burst_size())
    }

    /// 最大突发量（quic-go pacer.maxBurstSize）
    ///
    /// max(timeScaledBandwidth(MinPacingDelay+TimerGranularity),
    ///     maxBurstSizePackets × maxDatagramSize)
    /// - MinPacingDelay = 1ms, TimerGranularity = 1ms（quic-go params.go）
    /// - maxBurstSizePackets = 10（quic-go pacer.go maxBurstSizePackets）
    fn max_burst_size(&self) -> u64 {
        // quic-go timeScaledBandwidth(ns)：bw × ns / 1e9
        // ns = (1ms + 1ms) = 2ms = 2_000_000 ns
        let from_rate = if self.bandwidth > 0 {
            self.bandwidth * 2_000_000 / 1_000_000_000
        } else {
            0
        };
        let from_packets = (MAX_BURST_PACKETS * self.max_datagram_size) as u64;
        from_rate.max(from_packets)
    }

    /// 要等多久才有预算发下一包（quic-go pacer.TimeUntilSend）
    pub fn time_until_send(&self, now: Instant) -> Option<Duration> {
        let budget = self.budget(now);
        if budget >= self.max_datagram_size as u64 {
            return None;
        }
        if self.bandwidth == 0 {
            return None;
        }
        let deficit = (self.max_datagram_size as u64 - budget) as f64;
        let secs = deficit / self.bandwidth as f64;
        Some(Duration::from_secs_f64(secs).max(Duration::from_micros(1)))
    }
}

// ============================================================================
// CUBIC（quic-go cubic.go）
// ============================================================================

/// CUBIC 三次函数拥塞控制（TCP CUBIC 算法，quic-go cubic.go 移植）
pub struct Cubic {
    /// 上次丢包事件后的 epoch 起始时刻
    epoch: Option<Instant>,
    /// 上次丢包前的最大 cwnd（字节）
    last_max_cwnd: u64,
    /// epoch 开始后累计确认字节数
    acked_bytes_count: u64,
    /// TCP-Reno 等价 cwnd（字节，TCP-friendly 基线）
    estimated_tcp_cwnd: u64,
    /// CUBIC 曲线原点 cwnd（字节，即 W_max）
    origin_point_cwnd: u64,
    /// 到原点的时间（2^10 分之秒）
    time_to_origin_point: u32,
}

impl Default for Cubic {
    fn default() -> Self {
        Self::new()
    }
}

impl Cubic {
    pub fn new() -> Self {
        Self {
            epoch: None,
            last_max_cwnd: 0,
            acked_bytes_count: 0,
            estimated_tcp_cwnd: 0,
            origin_point_cwnd: 0,
            time_to_origin_point: 0,
        }
    }

    /// 重置（quic-go Cubic.Reset，RTO 后调用）
    pub fn reset(&mut self) {
        self.epoch = None;
        self.last_max_cwnd = 0;
        self.acked_bytes_count = 0;
        self.estimated_tcp_cwnd = 0;
        self.origin_point_cwnd = 0;
        self.time_to_origin_point = 0;
    }

    /// 应用层未充分利用窗口时重置 epoch（quic-go OnApplicationLimited）
    pub fn on_application_limited(&mut self) {
        self.epoch = None;
    }

    /// 丢包后计算新 cwnd（quic-go CongestionWindowAfterPacketLoss）
    ///
    /// 乘性减少 ×0.7。未达上次最大值用 betaLastMax=0.85 额外回退。
    fn cwnd_after_packet_loss(&mut self, current_cwnd: u64) -> u64 {
        let mss = MSS as u64;
        if current_cwnd + mss < self.last_max_cwnd {
            self.last_max_cwnd = (BETA_LAST_MAX * current_cwnd as f64) as u64;
        } else {
            self.last_max_cwnd = current_cwnd;
        }
        self.epoch = None;
        (BETA * current_cwnd as f64) as u64
    }

    /// ACK 后计算新 cwnd（quic-go CongestionWindowAfterAck）
    ///
    /// CUBIC 三次函数：W(t) = origin + C × (t - K)³
    fn cwnd_after_ack(
        &mut self,
        acked_bytes: u64,
        current_cwnd: u64,
        delay_min: Duration,
        event_time: Instant,
    ) -> u64 {
        self.acked_bytes_count += acked_bytes;
        let mss = MSS as u64;

        if self.epoch.is_none() {
            self.epoch = Some(event_time);
            self.acked_bytes_count = acked_bytes;
            self.estimated_tcp_cwnd = current_cwnd;
            if self.last_max_cwnd <= current_cwnd {
                self.time_to_origin_point = 0;
                self.origin_point_cwnd = current_cwnd;
            } else {
                let diff = self.last_max_cwnd.saturating_sub(current_cwnd);
                self.time_to_origin_point = integer_cube_root(cube_factor().saturating_mul(diff)) as u32;
                self.origin_point_cwnd = self.last_max_cwnd;
            }
        }

        let elapsed_us = self
            .epoch
            .map(|e| event_time.saturating_duration_since(e).as_micros() as u64)
            .unwrap_or(0);
        let delay_min_us = delay_min.as_micros() as u64;
        let elapsed = ((elapsed_us + delay_min_us) << 10) / 1_000_000;

        let offset = (self.time_to_origin_point as i64 - elapsed as i64).unsigned_abs();
        let delta = ((CUBE_CWND_SCALE * offset * offset) as u64 * mss) >> CUBE_SCALE;

        let target_cwnd = if elapsed > self.time_to_origin_point as u64 {
            self.origin_point_cwnd + delta
        } else {
            self.origin_point_cwnd.saturating_sub(delta)
        };
        let target_cwnd = target_cwnd.min(current_cwnd + self.acked_bytes_count / 2);

        let alpha = self.alpha();
        let tcp_inc = (self.acked_bytes_count as f64 * alpha * mss as f64
            / self.estimated_tcp_cwnd.max(1) as f64) as u64;
        self.estimated_tcp_cwnd += tcp_inc;
        self.acked_bytes_count = 0;

        target_cwnd.max(self.estimated_tcp_cwnd)
    }

    /// TCP-friendly alpha（quic-go alpha = 3 × N² × (1-beta) / (1+beta)）
    fn alpha(&self) -> f64 {
        3.0 * (1.0 - BETA) / (1.0 + BETA)
    }
}

/// cubeFactor = 1 << CUBE_SCALE / CUBE_CWND_SCALE / MSS（quic-go cubeFactor）
fn cube_factor() -> u64 {
    (1u64 << CUBE_SCALE) / CUBE_CWND_SCALE / MSS as u64
}

/// 整数立方根（用于 K = cbrt(C × diff)）
fn integer_cube_root(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut lo = 1u64;
    let mut hi = 2_097_152u64;
    while lo < hi {
        let mid = (lo + hi + 1) / 2;
        if mid * mid * mid <= n {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

// ============================================================================
// Hybrid Slow Start（quic-go hybrid_slow_start.go）
// ============================================================================

/// Hybrid Slow Start（TCP HyStart，quic-go hybrid_slow_start.go 移植）
pub struct HybridSlowStart {
    end_packet_number: u64,
    last_sent_packet_number: u64,
    started: bool,
    current_min_rtt: Duration,
    rtt_sample_count: u32,
    hystart_found: bool,
}

impl Default for HybridSlowStart {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridSlowStart {
    pub fn new() -> Self {
        Self {
            end_packet_number: 0,
            last_sent_packet_number: 0,
            started: false,
            current_min_rtt: Duration::ZERO,
            rtt_sample_count: 0,
            hystart_found: false,
        }
    }

    fn start_receive_round(&mut self, last_sent: u64) {
        self.end_packet_number = last_sent;
        self.current_min_rtt = Duration::ZERO;
        self.rtt_sample_count = 0;
        self.started = true;
    }

    fn is_end_of_round(&self, ack: u64) -> bool {
        self.end_packet_number < ack
    }

    /// 是否应退出慢启动（quic-go ShouldExitSlowStart）
    fn should_exit_slow_start(
        &mut self,
        latest_rtt: Duration,
        min_rtt: Duration,
        cwnd_packets: usize,
    ) -> bool {
        if !self.started {
            self.start_receive_round(self.last_sent_packet_number);
        }
        if self.hystart_found {
            return true;
        }
        self.rtt_sample_count += 1;
        if self.rtt_sample_count <= HYBRID_MIN_SAMPLES {
            if self.current_min_rtt == Duration::ZERO || self.current_min_rtt > latest_rtt {
                self.current_min_rtt = latest_rtt;
            }
        }
        if self.rtt_sample_count == HYBRID_MIN_SAMPLES {
            let mut threshold_us = min_rtt.as_micros() as u64 >> HYBRID_DELAY_FACTOR_EXP;
            threshold_us = threshold_us.min(HYBRID_DELAY_MAX_US);
            threshold_us = threshold_us.max(HYBRID_DELAY_MIN_US);
            let threshold = Duration::from_micros(threshold_us);
            if self.current_min_rtt > min_rtt + threshold {
                self.hystart_found = true;
            }
        }
        cwnd_packets >= HYBRID_LOW_WINDOW_PACKETS && self.hystart_found
    }

    fn on_packet_sent(&mut self, packet_number: u64) {
        self.last_sent_packet_number = packet_number;
    }

    fn on_packet_acked(&mut self, acked_packet_number: u64) {
        if self.is_end_of_round(acked_packet_number) {
            self.started = false;
        }
    }

    fn restart(&mut self) {
        self.started = false;
        self.hystart_found = false;
    }
}

// ============================================================================
// CUBIC Sender（quic-go cubic_sender.go）
// ============================================================================

/// 拥塞控制状态（quic-go qlog.CongestionState）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongState {
    SlowStart,
    CongestionAvoidance,
    Recovery,
    ApplicationLimited,
}

/// CUBIC 拥塞控制器（quic-go cubicSender 移植）
///
/// API 对齐 quic-go：
/// - on_packet_sent / on_packet_acked / on_congestion_event / can_send
/// - time_until_send / has_pacing_budget（pacer）
/// - bandwidth_estimate = cwnd / srtt × 5/4（pacer rate 源）
pub struct CubicSender {
    hybrid_slow_start: HybridSlowStart,
    cubic: Cubic,
    pacer: Pacer,

    largest_sent: u64,
    largest_acked: u64,
    largest_sent_at_last_cutback: u64,
    last_cutback_exited_slowstart: bool,

    /// 拥塞窗口（字节）
    cwnd: u64,
    /// 慢启动阈值（字节）
    ssthresh: u64,
    /// Reno ACK 计数
    num_acked_packets: u64,

    initial_cwnd: u64,
    max_cwnd: u64,

    state: CongState,
}

impl Default for CubicSender {
    fn default() -> Self {
        Self::new()
    }
}

impl CubicSender {
    /// 创建 CUBIC 控制器（初始 cwnd = 32 × MSS）
    pub fn new() -> Self {
        let initial_cwnd = (INITIAL_CWND_PACKETS * MSS) as u64;
        Self {
            hybrid_slow_start: HybridSlowStart::new(),
            cubic: Cubic::new(),
            pacer: Pacer::new(),
            largest_sent: 0,
            largest_acked: 0,
            largest_sent_at_last_cutback: 0,
            last_cutback_exited_slowstart: false,
            cwnd: initial_cwnd,
            ssthresh: u64::MAX,
            num_acked_packets: 0,
            initial_cwnd,
            max_cwnd: CWND_MAX as u64,
            state: CongState::SlowStart,
        }
    }

    /// 带宽估计（字节/秒）= cwnd / srtt × 5/4（quic-go BandwidthEstimate）
    ///
    /// quic-go: BandwidthFromDelta(cwnd, srtt) × adjustedBandwidth(×5/4)。
    /// srtt 为零时用 TimerGranularity（1ms）氶底，不作任何特殊处理。
    pub fn bandwidth_estimate(&self, srtt: Duration) -> u64 {
        let srtt = if srtt.is_zero() {
            Duration::from_millis(1) // quic-go TimerGranularity 兜底
        } else {
            srtt
        };
        let bw = (self.cwnd as f64 / srtt.as_secs_f64()) as u64;
        (bw as f64 * PACING_RATE_FACTOR) as u64
    }

    /// 当前 cwnd（字节）
    pub fn cwnd_bytes(&self) -> usize {
        self.cwnd as usize
    }

    /// 是否在恢复期（quic-go InRecovery）
    fn in_recovery(&self) -> bool {
        self.largest_acked != 0 && self.largest_acked <= self.largest_sent_at_last_cutback
    }

    /// 是否在慢启动（quic-go InSlowStart）
    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// 最小 cwnd（quic-go minCongestionWindow = 2 × MSS）
    fn min_cwnd(&self) -> u64 {
        (CWND_MIN_PACKETS * MSS) as u64
    }

    /// 记录发出一个包（quic-go OnPacketSent）
    pub fn on_packet_sent(
        &mut self,
        sent_time: Instant,
        packet_number: u64,
        bytes: usize,
        is_retransmittable: bool,
        srtt: Duration,
    ) {
        // pacer 记账（先更新 rate 再扣预算）
        self.pacer.set_bandwidth(self.bandwidth_estimate(srtt));
        self.pacer.sent_packet(sent_time, bytes);
        if !is_retransmittable {
            return;
        }
        self.largest_sent = packet_number;
        self.hybrid_slow_start.on_packet_sent(packet_number);
    }

    /// 收到 ACK（quic-go OnPacketAcked）
    pub fn on_packet_acked(
        &mut self,
        acked_packet: u64,
        acked_bytes: u64,
        prior_in_flight: u64,
        event_time: Instant,
        latest_rtt: Duration,
        min_rtt: Duration,
    ) {
        self.largest_acked = self.largest_acked.max(acked_packet);
        if self.in_recovery() {
            return;
        }
        self.maybe_increase_cwnd(acked_packet, acked_bytes, prior_in_flight, event_time, latest_rtt, min_rtt);
        if self.in_slow_start() {
            self.hybrid_slow_start.on_packet_acked(acked_packet);
        }
    }

    /// maybe_increase_cwnd（quic-go maybeIncreaseCwnd）
    fn maybe_increase_cwnd(
        &mut self,
        _acked_packet: u64,
        acked_bytes: u64,
        prior_in_flight: u64,
        event_time: Instant,
        latest_rtt: Duration,
        min_rtt: Duration,
    ) {
        if !self.is_cwnd_limited(prior_in_flight) {
            self.cubic.on_application_limited();
            self.state = CongState::ApplicationLimited;
            return;
        }
        if self.cwnd >= self.max_cwnd {
            return;
        }
        if self.in_slow_start() {
            self.cwnd += MSS as u64;
            self.state = CongState::SlowStart;
            let cwnd_pkts = (self.cwnd / MSS as u64) as usize;
            if self.hybrid_slow_start.should_exit_slow_start(latest_rtt, min_rtt, cwnd_pkts) {
                self.ssthresh = self.cwnd;
                self.state = CongState::CongestionAvoidance;
            }
            return;
        }
        self.state = CongState::CongestionAvoidance;
        self.num_acked_packets += 1;
        let new_cwnd = self.cubic.cwnd_after_ack(acked_bytes, self.cwnd, min_rtt, event_time);
        self.cwnd = new_cwnd.min(self.max_cwnd);
    }

    /// isCwndLimited（quic-go isCwndLimited）
    fn is_cwnd_limited(&self, bytes_in_flight: u64) -> bool {
        if bytes_in_flight >= self.cwnd {
            return true;
        }
        let available = self.cwnd - bytes_in_flight;
        let slow_start_limited = self.in_slow_start() && bytes_in_flight > self.cwnd / 2;
        slow_start_limited || available <= (MAX_BURST_PACKETS * MSS) as u64
    }

    /// 拥塞事件 / 丢包（quic-go OnCongestionEvent）
    pub fn on_congestion_event(
        &mut self,
        packet_number: u64,
        _lost_bytes: u64,
        _prior_in_flight: u64,
    ) {
        if packet_number <= self.largest_sent_at_last_cutback {
            return;
        }
        self.last_cutback_exited_slowstart = self.in_slow_start();
        self.state = CongState::Recovery;
        let new_cwnd = self.cubic.cwnd_after_packet_loss(self.cwnd);
        self.cwnd = new_cwnd.max(self.min_cwnd());
        self.ssthresh = self.cwnd;
        self.largest_sent_at_last_cutback = self.largest_sent;
        self.num_acked_packets = 0;
    }

    /// RTO 超时重传（quic-go OnRetransmissionTimeout）
    pub fn on_retransmission_timeout(&mut self, packets_retransmitted: bool) {
        self.largest_sent_at_last_cutback = 0;
        if !packets_retransmitted {
            return;
        }
        self.hybrid_slow_start.restart();
        self.cubic.reset();
        self.ssthresh = self.cwnd / 2;
        self.cwnd = self.min_cwnd();
        self.state = CongState::SlowStart;
    }

    /// 是否可发（quic-go CanSend：in_flight < cwnd）
    pub fn can_send(&self, bytes_in_flight: u64) -> bool {
        bytes_in_flight < self.cwnd
    }

    /// pacer 等待时长（quic-go TimeUntilSend）
    ///
    /// quic-go TimeUntilSend 完整移植：budget >= MSS 返回 0，
    /// 否则 deficit / bandwidth。不加自定义的 inflight 判断
    /// （quic-go 的应用层不放完 cwnd 就 application_limited 由
    /// cwnd 增长逻辑处理，不是靠 pacer 跳过）
    pub fn time_until_send(&self, now: Instant, srtt: Duration) -> Option<Duration> {
        let bw = self.bandwidth_estimate(srtt);
        let mut p = Pacer::new();
        p.set_bandwidth(bw);
        p.budget_at_last_sent = self.pacer.budget_at_last_sent;
        p.last_sent_time = self.pacer.last_sent_time;
        p.initialized = self.pacer.initialized;
        p.time_until_send(now)
    }

    /// pacer 预算是否够（quic-go HasPacingBudget）
    pub fn has_pacing_budget(&self, now: Instant, srtt: Duration) -> bool {
        self.time_until_send(now, srtt).is_none()
    }

    /// 记录 pacer 发送
    pub fn pacer_sent(&mut self, now: Instant, size: usize, srtt: Duration) {
        self.pacer.set_bandwidth(self.bandwidth_estimate(srtt));
        self.pacer.sent_packet(now, size);
    }

    /// 当前状态
    pub fn state(&self) -> CongState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_cwnd() {
        let c = CubicSender::new();
        assert_eq!(c.cwnd_bytes(), 32 * MSS);
    }

    #[test]
    fn test_slow_start_growth() {
        let mut c = CubicSender::new();
        let now = Instant::now();
        // 模拟有在途数据的 ACK（prior_in_flight 接近 cwnd 才算 cwnd_limited）
        let inflight = (30 * MSS) as u64; // 接近初始 cwnd 32×MSS
        for i in 1..=10 {
            c.on_packet_acked(i, MSS as u64, inflight, now, Duration::from_millis(1), Duration::from_millis(1));
        }
        assert!(c.cwnd_bytes() > 32 * MSS, "慢启动 cwnd 应增长: {}", c.cwnd_bytes());
    }

    #[test]
    fn test_loss_backoff() {
        let mut c = CubicSender::new();
        let now = Instant::now();
        for i in 1..=100 {
            c.on_packet_acked(i, MSS as u64, 0, now, Duration::from_millis(1), Duration::from_millis(1));
        }
        let before = c.cwnd_bytes();
        c.on_congestion_event(200, MSS as u64, 0);
        assert!(c.cwnd_bytes() < before, "丢包后应回退: {} -> {}", before, c.cwnd_bytes());
        assert!(c.cwnd_bytes() >= 2 * MSS, "不低于最小 cwnd: {}", c.cwnd_bytes());
    }

    #[test]
    fn test_can_send() {
        let c = CubicSender::new();
        assert!(c.can_send(0));
        assert!(c.can_send((31 * MSS) as u64));
        assert!(!c.can_send((33 * MSS) as u64));
    }

    #[test]
    fn test_bandwidth_estimate() {
        let c = CubicSender::new();
        let bw = c.bandwidth_estimate(Duration::from_millis(10));
        assert!(bw > 4_000_000, "带宽估计应 ~5MB/s: {}", bw);
    }

    #[test]
    fn test_pacer_initial_burst() {
        let c = CubicSender::new();
        let now = Instant::now();
        assert!(c.has_pacing_budget(now, Duration::from_millis(1)));
    }
}
