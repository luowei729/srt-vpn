//! quic/congctl.rs — 拥塞控制（自研 QUIC 语义）
//!
//! 目标（重构共识决策 F）：学 QUIC 流控跑满带宽，单连接共享拥塞窗口。
//!
//! 为什么用 BBR 风格（对比 CUBIC/NewReno）：
//! - 公网高 RTT 场景：CUBIC/NewReno 以"丢包即减窗"为拥塞信号，在高 RTT 下
//!   慢启动慢、丢包敏感，窗口=带宽×RTT 但需主动探测，容易到下界
//! - BBR 以"带宽×RTT 积"为模型：持续探测最大带宽（max_bw）与最小 RTT
//!   （min_rtt），目标直接是 BDP（Bandwidth-Delay Product），在高 RTT 下
//!   天然能打满链路（hy2 也推荐 BBR 做兜底）
//!
//! 实现（借鉴 BBR v1 简化）：
//! - 状态：STARTUP（加速）/ DRAIN（排水）/ PROBE_BW（带宽探测）/ PROBE_RTT
//! - STARTUP：每轮 ACK 窗口 ×2（慢启动），直到带宽不再增长（Pacing Gain 探深）
//! - PROBE_BW：在 1.25/0.75/1.0 增益间周期巡航，找最大带宽
//! - 发送速率 = max_bw × pacing_gain；窗口 = 发送速率 × min_rtt
//!
//! 返回给上层：should_send(now, in_flight, inflight_bytes) -> 是否可发下一包，
//! 以及 pacing 间隔（发送节流）。

use std::time::{Duration, Instant};

/// BBR 参数
const STARTUP_GAIN: f64 = 2.885; // 慢启动增益（BBR v1 标准 2.885）
const DRAIN_GAIN: f64 = 0.5; // 排水增益
const PROBE_BW_GAIN_HI: f64 = 1.25; // 探测带宽高增益
const PROBE_BW_GAIN_LO: f64 = 0.75; // 探测带宽低增益
const PROBE_BW_GAIN_CRUISE: f64 = 1.0; // 巡航增益
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10); // 每 10s 一次 RTT 探测
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
const BANDWIDTH_FILTER_WINDOW: usize = 10; // 带宽估计的窗口长度

/// BBR 状态机
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrState {
    /// 启动加速（指数增长）
    Startup,
    /// 排水（慢启动结束，排出积压）
    Drain,
    /// 带宽探测巡航（周期性 1.25/0.75）
    ProbeBw,
    /// RTT 探测（周期降低发送速率，测 min_rtt）
    ProbeRtt,
}

/// BBR 拥塞控制器
pub struct Bbr {
    /// 状态
    pub state: BbrState,
    /// 估计的最大带宽（字节/秒）
    pub max_bw: f64,
    /// 估计的最小 RTT
    pub min_rtt: Duration,
    /// 平滑发送速率（字节/秒）
    pub pacing_rate: f64,
    /// 当前拥塞窗口（字节）
    pub cwnd: usize,
    /// 最小拥塞窗口（4 包 × MSS，BBR 惯例）
    pub cwnd_min: usize,
    /// 带宽样本环形缓冲
    bw_samples: std::collections::VecDeque<f64>,
    /// 上一轮确认的字节数（带宽计算用）
    last_acked_bytes: u64,
    /// 当前 pacing gain
    pacing_gain: f64,
    /// 当前 cwnd gain
    cwnd_gain: f64,
    /// STARTUP 中连续轮次看是否仍在增长（退出慢启动判定）
    startup_rounds_without_growth: u32,
    /// 上次面包屑（带宽跟踪）
    last_round_bw: f64,
    /// 本轮是否已确认过（轮次追踪）
    round_start: bool,
    /// RTT 探测计时器
    probe_rtt_time: Instant,
    /// RTT 探测结束时间
    probe_rtt_done_at: Option<Instant>,
    /// 上次发送时刻（pacing）
    last_send_time: Instant,
}

impl Default for Bbr {
    fn default() -> Self {
        Self::new()
    }
}

impl Bbr {
    /// 创建 BBR 控制器（MSS 默认 1316，与外壳 payload 对齐）
    pub fn new() -> Self {
        let mss = 1316;
        Self {
            state: BbrState::Startup,
            max_bw: 0.0,
            min_rtt: Duration::from_millis(100), // 初始假设 100ms
            pacing_rate: 0.0,
            cwnd: 16 * mss, // 初始窗口 16 包
            cwnd_min: 4 * mss,
            bw_samples: std::collections::VecDeque::new(),
            last_acked_bytes: 0,
            pacing_gain: STARTUP_GAIN,
            cwnd_gain: STARTUP_GAIN,
            startup_rounds_without_growth: 0,
            last_round_bw: 0.0,
            round_start: false,
            probe_rtt_time: Instant::now() + PROBE_RTT_INTERVAL,
            probe_rtt_done_at: None,
            last_send_time: Instant::now(),
        }
    }

    /// 每收到一个 ACK（确认了 bytes 字节）时调用，更新带宽/窗口/状态
    pub fn on_ack(&mut self, bytes_acked: u64, rtt: Duration) {
        // 更新 min_rtt
        if rtt < self.min_rtt {
            self.min_rtt = rtt;
        }
        self.last_acked_bytes += bytes_acked;
        // 轮次结束（由外部按"每 RTT 一次"调用 on_ack 且累计达到仍在途量时切轮）
        // 简化：每次 on_ack 视为一个 ACK 事件，带宽增量直接累积，
        // 由 on_round 每 RTT 汇总一次（见 connection.rs 调度）
        self.round_start = true;
    }

    /// RTT 轮次结束（每次 RTT 间隔由外层调用）：汇总带宽样本，切换状态机
    pub fn on_round(&mut self, round_duration: Duration) {
        if round_duration.is_zero() {
            return;
        }
        // 本轮带宽样本 = 已确认字节 / 轮时长
        let bw = self.last_acked_bytes as f64 / round_duration.as_secs_f64();
        self.last_acked_bytes = 0;
        if bw > 0.0 {
            self.bw_samples.push_back(bw);
            if self.bw_samples.len() > BANDWIDTH_FILTER_WINDOW {
                self.bw_samples.pop_front();
            }
            // max_bw = 窗口内最大（BBR 用最大递增滤波）
            let max = self.bw_samples.iter().cloned().fold(0.0f64, f64::max);
            if max > self.max_bw {
                self.max_bw = max;
            }
        }
        self.update_state_and_rate();
        self.round_start = false;
    }

    /// 用当前估计更新发送速率与窗口
    fn update_state_and_rate(&mut self) {
        // 状态转移
        match self.state {
            BbrState::Startup => {
                // STARTUP：若带宽不再增长（连续 ≥3 轮增速 < 25%），进入 DRAIN
                if self.last_round_bw > 0.0 {
                    let growth = (self.max_bw - self.last_round_bw) / self.last_round_bw;
                    if growth < 0.25 {
                        self.startup_rounds_without_growth += 1;
                    } else {
                        self.startup_rounds_without_growth = 0;
                    }
                }
                self.last_round_bw = self.max_bw;
                if self.startup_rounds_without_growth >= 3 {
                    self.state = BbrState::Drain;
                    self.pacing_gain = DRAIN_GAIN;
                    self.cwnd_gain = DRAIN_GAIN;
                } else {
                    self.pacing_gain = STARTUP_GAIN;
                    self.cwnd_gain = STARTUP_GAIN;
                }
            }
            BbrState::Drain => {
                // 排水：cwnd 回到 1.0 增益（无积压）即入 PROBE_BW
                let bdp_bytes = (self.max_bw * self.min_rtt.as_secs_f64()) as usize;
                if self.cwnd <= bdp_bytes * 3 {
                    self.state = BbrState::ProbeBw;
                    self.pacing_gain = PROBE_BW_GAIN_CRUISE;
                    self.cwnd_gain = 2.0;
                }
            }
            BbrState::ProbeBw => {
                // 带宽探测巡航：照常（增益变化由时间驱动，见 probe_bw_cycle）
                self.cwnd_gain = 2.0;
            }
            BbrState::ProbeRtt => {
                // RTT 探测结束返回 ProbeBw
                self.state = BbrState::ProbeBw;
                self.pacing_gain = PROBE_BW_GAIN_CRUISE;
                self.cwnd_gain = 2.0;
            }
        }

        // 计算 pacing rate = max_bw × pacing_gain
        if self.max_bw > 0.0 {
            self.pacing_rate = self.max_bw * self.pacing_gain;
        }
        // 计算 cwnd = 足够覆盖 BDP × cwnd_gain（下限 cwnd_min）
        let bdp_bytes = (self.max_bw * self.min_rtt.as_secs_f64()) as usize;
        let target = if bdp_bytes > 0 {
            (bdp_bytes as f64 * self.cwnd_gain) as usize
        } else {
            self.cwnd_min
        };
        self.cwnd = target.max(self.cwnd_min);
        // RTT 探测调度
        let now = Instant::now();
        if now >= self.probe_rtt_time && self.state != BbrState::ProbeRtt {
            self.state = BbrState::ProbeRtt;
            self.pacing_gain = 0.5;
            self.probe_rtt_done_at = Some(now + PROBE_RTT_DURATION);
        }
        if let Some(done) = self.probe_rtt_done_at {
            if now >= done {
                // 重置 min_rtt（为下一轮探测重新测量）
                self.min_rtt = Duration::from_millis(100);
                self.probe_rtt_done_at = None;
                self.state = BbrState::ProbeBw;
                self.pacing_gain = PROBE_BW_GAIN_CRUISE;
            }
        }
    }

    /// 带宽探测周期性增益（PROBE_BW 阶段由时间驱动切换 1.25/0.75/1.0）
    pub fn probe_bw_cycle(&mut self, now: Instant) {
        if self.state != BbrState::ProbeBw {
            return;
        }
        // 周期 8 个 RTT 长度（简化固定 1s）
        const CYCLE: Duration = Duration::from_secs(1);
        let elapsed = now.duration_since(self.last_send_time); // 用上次发送时间近似轮次
        if elapsed > CYCLE {
            // 在 h/l/cruise 间轮转
            self.pacing_gain = if self.pacing_gain >= PROBE_BW_GAIN_HI {
                PROBE_BW_GAIN_LO
            } else if self.pacing_gain <= PROBE_BW_GAIN_LO {
                PROBE_BW_GAIN_CRUISE
            } else {
                PROBE_BW_GAIN_HI
            };
            self.last_send_time = now;
        }
    }

    /// 拥塞事件（丢包/超时重传时调用）：降低速率与窗口（BBR 不只靠丢包，
    /// 但持续超时说明带宽估计过高，做防御性回退）
    pub fn on_congestion(&mut self) {
        // 保留当前 max_bw 的 0.7（避免完全崩溃，BBR 对丢包不敏感）
        self.max_bw *= 0.7;
        self.pacing_rate = self.max_bw * self.pacing_gain;
        let bdp = (self.max_bw * self.min_rtt.as_secs_f64()) as usize;
        self.cwnd = (bdp * 2).max(self.cwnd_min);
    }

    /// 是否允许发送一个数据包（外部连接调度调用）
    ///
    /// - 超出拥塞窗口：不发送
    /// - 满足 pacing 间隔：可发（还返回下一次可发的时间间隔给发送节流）
    pub fn can_send(&self, now: Instant, inflight_bytes: usize) -> bool {
        // 窗口检查
        if inflight_bytes >= self.cwnd {
            return false;
        }
        // pacing 检查（速率 >0 时）
        if self.pacing_rate > 0.0 {
            let interval = (1316.0 / self.pacing_rate).max(1e-6); // 每包间隔（秒）
            let elapsed = now.duration_since(self.last_send_time).as_secs_f64();
            if elapsed < interval {
                return false;
            }
        }
        true
    }

    /// 发送一个包后调用（更新 last_send_time）
    pub fn on_send(&mut self, now: Instant) {
        self.last_send_time = now;
    }

    /// 当前拥塞窗口字节数
    pub fn cwnd_bytes(&self) -> usize {
        self.cwnd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CAN_SEND 窗口限制基本行为
    #[test]
    fn test_can_send_window() {
        let mut bbr = Bbr::new();
        let now = Instant::now();
        // 初始窗口 16×1316 = 21056，inflight 小于窗口可发
        assert!(bbr.can_send(now, 0));
        // 模拟填满窗口则拒绝
        assert!(!bbr.can_send(now, bbr.cwnd_bytes()));
        // 更新后窗口变大再可发
        bbr.on_ack(100_000, Duration::from_millis(50));
        // 短暂轮次模拟带宽建立
        bbr.on_round(Duration::from_millis(100));
        assert!(bbr.cwnd_bytes() > 16 * 1316, "慢启动后窗口应增长");
    }

    /// 带宽累计后窗口应覆盖 BDP
    #[test]
    fn test_bdp_window() {
        let mut bbr = Bbr::new();
        // 模拟高带宽：每 RTT 20ms 确认 50KB
        for _ in 0..10 {
            bbr.on_ack(50_000, Duration::from_millis(20));
            bbr.on_round(Duration::from_millis(20));
        }
        // max_bw ≈ 50KB/20ms = 2.5MB/s；BDP(2.5MB/s × 20ms) = 50KB
        assert!(bbr.max_bw > 2_000_000.0, "带宽估计应 ~2.5MB/s: {}", bbr.max_bw);
        assert!(bbr.cwnd_bytes() >= 50_000, "窗口应 ≥ BDP: {}", bbr.cwnd_bytes());
    }
}