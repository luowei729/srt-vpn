//! tunnel/multiplex.rs — 多路复用层（核心）
//!
//! 设计决策（Q7/Q14）：
//! - 单 SRT 连接 + 多路复用层：所有会话共享一条 SRT 隧道
//! - 单层可靠模型：可靠传输完全交给 SRT 层（udp_mode 配置 socket 参数）
//!   复用层只做：分帧（会话 ID 路由）+ 调度（公平排队）+ 窗口流控
//! - （2026-08-19 更新）TS 伪装层已移除，隧道帧直接作为 SRT 消息发送
//! 帧头 v2（15 字节，长度与布局同 v1）：Magic + Version + Type + SessionID + Len + Seq + Flags
//!
//! v2 变更（2026-10-05，0.6.3）：仅 Seq(u32) 的语义变更——高 8bit = 会话代次 epoch，
//! 低 24bit = 会话内帧序号（Open 恒为 0）。作用等价于 QUIC STREAM frame 的 offset：
//! 让每条会话在 SRT 乱序投递（inorder=0）下仍能各自按序交付，且一条会话丢包不再
//! 冻结其他会话（消除跨会话队头阻塞）。
//!
//! 帧大小约束：帧头 15 字节 + payload ≤ 1316（SRT 消息上限），
//! 单帧数据 payload ≤ 1301 字节；大数据分片为多帧。

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Mutex;

use super::{
    FrameType, FRAME_HEADER_LEN, PROTOCOL_VERSION, TUNNEL_MAGIC,
    FLAG_DIR_ACCEPT, FLAG_RELIABLE, FLAG_WINDOW,
};

/// 单帧数据 payload 上限（SRT 原生 payload 1316 - 帧头 15 = 1301）
/// 2026-08-19：移除 TS 伪装层，使用 SRT 官方默认 payload（1316B）。
pub const FRAME_DATA_MAX: usize = 1301;

/// Seq 字段拆分：高 8bit 为 epoch，低 24bit 为会话内序号
const EPOCH_BITS: u32 = 24;
/// 会话内序号可用上限（16,777,215 帧 ≈ 21GB/会话，超出则换 epoch 重开序号空间）
const SEQ_MASK: u32 = (1 << EPOCH_BITS) - 1;

/// 该帧类型是否参与“会话内有序”（= QUIC stream 语义覆盖的帧集合）
///
/// Open/Data/Fin/Close 必须按会话顺序交付：半关闭（B2）语义要求 Fin/Close 不得
/// 早于已发出的 Data 被处理。其余帧（Ack/Heartbeat/Challenge/Response/Rst/Datagram）
/// 是幂等控制帧或实时数据报，直接投递，不进重排缓冲（否则心跳会被丢包空洞拖延）。
pub fn uses_session_order(ftype: FrameType) -> bool {
    matches!(
        ftype,
        FrameType::Open | FrameType::Data | FrameType::Fin | FrameType::Close
    )
}

/// 编码后的复用层帧
#[derive(Debug, Clone)]
pub struct Frame {
    /// 帧类型
    pub ftype: FrameType,
    /// 会话 ID
    pub session_id: u16,
    /// 序号字段：v2 = [epoch:8 | 会话内序号:24]；非会话帧 epoch=0（仅诊断用）
    pub seq: u32,
    /// 标志位
    /// （P1 后半段接入半关闭/流控时启用）
    #[allow(dead_code)]
    pub flags: u8,
    /// payload（已按会话路由）
    pub payload: Vec<u8>,
}

/// 每会话发送状态（v0.6.3）
struct SidTx {
    /// 当前会话代次（sid 被复用时递增，接收端据此隔离旧会话残留帧）
    epoch: u8,
    /// 下一个会话内序号
    seq: u32,
}

/// 多路复用编码器（发送方向）
pub struct MuxEncoder {
    /// 非会话帧的全局序号（epoch 段固定为 0，不参与重排）
    seq: AtomicU32,
    /// 每会话发送状态表（sid -> epoch/seq）—— sid 空间仅 1..=255，表大小天然有界
    session_tx: Mutex<HashMap<u16, SidTx>>,
    /// epoch 分配器（1..=255 循环；0 保留给非会话帧）
    epoch_ctr: AtomicU8,
    /// 可靠模式标记（写入每帧标志位，对端据此适配）
    reliable: bool,
    /// 本端在会话里的方向：true=服务端（回传方向，帧带 FLAG_DIR_ACCEPT）；
    /// false=发起方/客户端（opener 方向，首帧为 Open）。
    /// 一条 SRT 连接上本端发出的帧只属于一个方向，所以这是编码器属性而非逐帧参数。
    dir_acceptor: bool,
}

impl MuxEncoder {
    /// 创建编码器（发起方方向：客户端 / 服务端向发起方回发以外的控制帧）
    pub fn new(reliable: bool) -> Self {
        Self {
            seq: AtomicU32::new(0),
            session_tx: Mutex::new(HashMap::new()),
            epoch_ctr: AtomicU8::new(0),
            reliable,
            dir_acceptor: false,
        }
    }

    /// 创建“回传方向”编码器（服务端用）：会话帧带 FLAG_DIR_ACCEPT，
    /// 告知对端“本帧属于 acceptor→opener 方向”，接收端据此走独立的序号空间
    pub fn new_acceptor(reliable: bool) -> Self {
        Self {
            dir_acceptor: true,
            ..Self::new(reliable)
        }
    }

    /// 分配一个新 epoch（1..=255，0 表示“不参与重排”）
    fn alloc_epoch(&self) -> u8 {
        let raw = self.epoch_ctr.fetch_add(1, Ordering::Relaxed) as u16;
        ((raw % 255) as u8) + 1
    }

    /// 计算一帧的 Seq 字段
    ///
    /// 会话帧（Open/Data/Fin/Close）：同一 sid 内单调递增，Open 恒为该代次的 0；
    /// 收到新的 Open 说明 sid 被复用 → 换 epoch，旧会话在途帧在接收端会被判 stale 丢弃，
    /// 从根上消除“旧会话残留帧污染新会话”（0.6.2 数据错乱的两个根因之一）。
    fn next_seq_field(&self, ftype: FrameType, session_id: u16) -> u32 {
        if !uses_session_order(ftype) {
            // 控制/数据报帧：epoch=0，低 24bit 用全局计数（仅供日志诊断顺序跳变）
            return self.seq.fetch_add(1, Ordering::Relaxed) & SEQ_MASK;
        }
        let mut map = self.session_tx.lock().unwrap();
        let tx = map.entry(session_id).or_insert(SidTx { epoch: 0, seq: 0 });
        if tx.epoch == 0 || matches!(ftype, FrameType::Open) {
            // 首次使用该 sid，或收到新 Open（= sid 复用/新会话建立）→ 新代次，序号归零
            tx.epoch = self.alloc_epoch();
            tx.seq = 0;
        } else if tx.seq >= SEQ_MASK {
            // 单会话已达 ~16.7M 帧（≈21GB）：换 epoch 重开序号空间，避免 24bit 回绕静默错乱
            tracing::warn!(session = session_id, "会话内帧序号将回绕，切换 epoch 重开序号空间");
            tx.epoch = self.alloc_epoch();
            tx.seq = 0;
        }
        let field = ((tx.epoch as u32) << EPOCH_BITS) | tx.seq;
        tx.seq += 1;
        field
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
        // 序号 (u32 BE)：v2 = [epoch:8 | 会话内序号:24]（非会话帧 epoch=0）
        frame.extend_from_slice(&self.next_seq_field(ftype, session_id).to_be_bytes());
        // 标志位：可靠模式标记 + 会话方向位 + 调用方标志
        let mut f = flags;
        if self.reliable {
            f |= FLAG_RELIABLE;
        }
        // v0.6.3：服务端发出的会话帧标为“回传方向”，与发起方方向的序号空间分开
        if self.dir_acceptor {
            f |= FLAG_DIR_ACCEPT;
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
pub fn heartbeat_timestamp(payload: &[u8]) -> Option<i64> {
    if payload.len() != 8 {
        return None;
    }
    Some(i64::from_le_bytes(payload.try_into().ok()?))
}

/// 每会话重排状态（v0.6.3）
struct SidReorder {
    /// 当前会话代次（与帧头 epoch 比对，旧代次残留帧一律丢弃）
    epoch: u8,
    /// 下一个期望交付的会话内序号
    next: u32,
    /// 乱序缓冲：会话内序号 -> 帧（等空洞补齐后按序放行）
    buf: BTreeMap<u32, Frame>,
}

/// Open 尚未到达时的暂存上限（每会话）——防止对端异常时无界堆积
const PREOPEN_MAX: usize = 64;
/// 每会话乱序缓冲上限（空洞长时间补不上时不再增长，宁可断该会话也不撑爆内存）
const REORDER_MAX: usize = 4096;

/// 多路复用解码器（接收方向）
pub struct MuxDecoder {
    /// 每会话**每方向**的重排状态：(sid, 是否回传方向) -> 状态。
    /// 为何按方向分开：Open 只在发起方→对端方向存在，而两个方向的帧共用同一 sid，
    /// 若共用一份序号状态会把彼此判为“空洞/旧代次”（0.6.3 首版在此卡死下载）。
    /// 这与 QUIC “一条 stream 两个方向各自维护 offset”完全同构。
    states: HashMap<(u16, bool), SidReorder>,
    /// Open 晚于本会话数据帧到达时的暂存队列（**仅发起方方向**使用）
    /// （0.6.2 当时选择“直投”导致会话未建立就收到数据、触发 Rst 洪水与错序写入）
    preopen: HashMap<u16, Vec<Frame>>,
    /// 诊断：确实发生乱序投递的次数
    /// （>0 说明 SRT inorder=0 已生效、跨会话队头阻塞真正被打破；恒为 0 则说明
    ///   乱序投递未发生，重排层就只是个开销而拿不到收益——上线后必须看这个值）
    pub out_of_order: u64,
    /// 诊断：丢弃的旧代次/重复/溢出帧数
    pub stale_dropped: u64,
    /// 周期诊断日志的上次输出时间（v0.6.3）
    last_report: Option<std::time::Instant>,
    /// 已处理帧计数（用于每 512 帧触发一次周期诊断，避免作改变调用点形式）
    rx_frames: u64,
}

impl Default for MuxDecoder {
    fn default() -> Self {
        Self {
            states: HashMap::new(),
            preopen: HashMap::new(),
            out_of_order: 0,
            stale_dropped: 0,
            last_report: None,
            rx_frames: 0,
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

        // v0.6.3：会话内顺序由 feed() 的每会话重排保证，此处不再做全局连续性检测
        //（旧的全局 seq 连续性日志在 inorder=0 下会刷屏且已无意义）

        Some(Frame {
            ftype,
            session_id,
            seq,
            flags,
            payload,
        })
    }

    /// 解析 SRT 消息 + 每会话重排，返回“此刻可按序交付”的帧集合（v0.6.3 生产入口）
    ///
    /// 设计目标（对应 hy2 “每 TCP 连接 = 一条独立 QUIC stream”的语义）：
    /// - 会话间隔离：某会话出现空洞只缓冲它自己的后续帧，其他会话照常放行（消除 HOL）；
    /// - 会话内有序：靠 [epoch | 会话内序号] 补齐空洞后按序交付，保证 TCP 字节流不错乱；
    /// - sid 复用安全：旧会话在途残留帧因 epoch 不同被丢弃，绝不污染新会话。
    pub fn feed(&mut self, msg: &[u8]) -> Vec<Frame> {
        // v0.6.3：入口周期诊断（挂在共用入口而非各调用点，避免漏挂）；每 512 帧看一次时间
        self.rx_frames += 1;
        if self.rx_frames % 512 == 0 {
            self.report_now();
        }
        let Some(frame) = self.decode_frame(msg) else {
            return Vec::new();
        };
        // 非会话帧（心跳/Ack/认证/Rst/UDP 数据报）立即投递：
        // 它们幂等或实时，绕重排可避免被某个丢包会话的空洞拖延（心跳保活的关键）
        if !uses_session_order(frame.ftype) {
            return vec![frame];
        }
        let epoch = (frame.seq >> EPOCH_BITS) as u8;
        let sseq = frame.seq & SEQ_MASK;
        let sid = frame.session_id;
        if epoch == 0 {
            // 无代次标记（异常帧）→ 直投不误杀，正常两端版本下不会出现（版本校验会先拒收）
            return vec![frame];
        }
        // v0.6.3：按 (sid, 方向) 维护状态。Open 只存在于发起方→对端方向，
        // 而两个方向的帧共用同一个 sid，必须分开重排（=QUIC 每 stream 双向各自 offset）
        let dir_acceptor = frame.flags & FLAG_DIR_ACCEPT != 0;
        let key = (sid, dir_acceptor);

        if matches!(frame.ftype, FrameType::Open) {
            // 新会话建立（或 sid 复用）：重建该会话的重排状态，旧状态直接丢弃
            let waiting = self.preopen.remove(&sid).unwrap_or_default();
            let mut st = SidReorder {
                epoch,
                next: sseq + 1,
                buf: BTreeMap::new(),
            };
            let mut out = Vec::with_capacity(waiting.len() + 8);
            // Open 自身最先交付（会话由此在注册表建立）
            out.push(frame);
            // 并入 Open 之前暂存的同代次帧；异代次（上一会话残留）丢弃
            for f in waiting {
                let e = (f.seq >> EPOCH_BITS) as u8;
                let s = f.seq & SEQ_MASK;
                if e != epoch || s < st.next || st.buf.len() >= REORDER_MAX {
                    self.drop_stale();
                    continue;
                }
                st.buf.insert(s, f);
            }
            flush_ready(&mut st, &mut out);
            self.states.insert(key, st);
            return out;
        }

        match self.states.get_mut(&key) {
            Some(st) if st.epoch == epoch => {
                if sseq < st.next {
                    // 重复帧（SRT 重传导致的重复交付）→ 丢弃，保证不重复写入
                    self.drop_stale();
                    return Vec::new();
                }
                if sseq == st.next {
                    st.next += 1;
                    let mut out = vec![frame];
                    // 连带冲刷缓冲里已补齐的连续段
                    flush_ready(st, &mut out);
                    out
                } else {
                    // 超前帧：说明出现了空洞（前面的帧还在重传路上）→ 只缓冲本会话，
                    // 不阻塞其他会话，这正是“消除跨会话队头阻塞”的现场
                    self.out_of_order += 1;
                    // 写入全局指标：这是“乱序投递确实发生、跨会话 HOL 真被打破”的硬证据；
                    // 上线后若恒为 0，说明 inorder=0 未生效，重排只是白付开销。
                    let m = crate::metrics::metrics();
                    m.reorder_out_of_order
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if st.buf.len() < REORDER_MAX {
                        st.buf.insert(sseq, frame);
                        // 缓冲深度峰值：持续高位 = 空洞很久补不上（重传在追赶）
                        m.reorder_buffered
                            .fetch_max(st.buf.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    } else {
                        // 缓冲已满：空洞久未补齐，丢弃新到帧并告警（宁可坏一条会话）
                        // 先取出 gap 作为对 st 的最后一道使用，后续才能调 &mut self 方法写指标
                        let gap = sseq - st.next;
                        self.drop_stale();
                        tracing::warn!(session = sid, gap, "重排缓冲溢出");
                    }
                    Vec::new()
                }
            }
            // 代次不同：区分“更新”（sid 复用后的新会话）与“更旧”（上一会话在途残留）。
            // 用回绕安全比较：u8 环形距离 <128 则为更新，否则为陈旧帧。
            Some(st) => {
                let newer = epoch.wrapping_sub(st.epoch) < 128;
                if !newer {
                    // 旧会话残留帧 → 丢弃，绝不污染新会话
                    self.drop_stale();
                    return Vec::new();
                }
                // 新代次首帧（Open 已在另一分支处理；这里常见于回传方向的新会话首帧）
                let mut st2 = SidReorder {
                    epoch,
                    next: sseq + 1,
                    buf: BTreeMap::new(),
                };
                let mut out = vec![frame];
                flush_ready(&mut st2, &mut out);
                self.states.insert(key, st2);
                out
            }
            // 本方向尚无状态
            None => {
                if dir_acceptor {
                    // 回传方向永远没有 Open 帧（Open 只在发起方→对端方向）：首帧即建基线。
                    // 0.6.3 首版误在此也“等 Open”，导致客户端把全部下行数据塞进 preopen
                    // 直到溢出丢弃（netem 有损回环实测 82065 条告警、下载完全卡死）。
                    let mut st = SidReorder {
                        epoch,
                        next: sseq + 1,
                        buf: BTreeMap::new(),
                    };
                    let mut out = vec![frame];
                    flush_ready(&mut st, &mut out);
                    self.states.insert(key, st);
                    out
                } else {
                    // 发起方方向：必须等 Open 建立会话（本端注册表还没有该 sid，
                    // 直投会“无法路由→Rst”），先有界暂存，Open 到齐后按序并入
                    let v = self.preopen.entry(sid).or_default();
                    if v.len() < PREOPEN_MAX {
                        v.push(frame);
                    } else {
                        self.drop_stale();
                        tracing::warn!(session = sid, "Open 长时间未到，暂存已满，丢弃数据帧");
                    }
                    Vec::new()
                }
            }
        }
    }

    /// 诊断：当前全部会话的重排缓冲帧数（供单测/未来诊断接口使用）
    #[allow(dead_code)]
    pub fn buffered_frames(&self) -> usize {
        self.states.values().map(|s| s.buf.len()).sum::<usize>()
            + self.preopen.values().map(|v| v.len()).sum::<usize>()
    }

    /// 记录一次“旧代次/重复/溢出”丢弃（异常路径低频，直接写全局指标便于真机定位）
    fn drop_stale(&mut self) {
        self.stale_dropped += 1;
        crate::metrics::metrics()
            .reorder_stale_dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// 周期性输出重排现场（每 5s 最多一条 INFO）
    ///
    /// 为什么必须走日志而不仅靠 metrics HTTP：本次 netem 实验发现配了 metrics_port
    /// 但服务从未 bind（既无“已启动”也无“异常”日志），而“乱序是否真的发生、空洞是否
    /// 补得上”是判定 inorder=0 方案成败的唯一依据；真机上日志也比开端口更容易拿。
    pub fn report_now(&mut self) {
        let now = std::time::Instant::now();
        match self.last_report {
            Some(t) if t.elapsed().as_secs() < 5 => return,
            _ => self.last_report = Some(now),
        }
        // 完全无乱序无丢弃时不打日志（空闲期不刷屏），但首次仍打一条建立基线
        let buffered = self.buffered_frames();
        if self.out_of_order == 0 && self.stale_dropped == 0 && buffered == 0 {
            return;
        }
        tracing::info!(
            out_of_order = self.out_of_order,
            stale_dropped = self.stale_dropped,
            buffered = buffered,
            states = self.states.len(),
            "复用层重排现场"
        );
    }
}

/// 从乱序缓冲中取走已补齐的连续段（按序放行）
fn flush_ready(st: &mut SidReorder, out: &mut Vec<Frame>) {
    while let Some(f) = st.buf.remove(&st.next) {
        st.next += 1;
        out.push(f);
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

    // ==============================================================
    // v0.6.3 每会话重排（MuxDecoder::feed）单测
    // 这三组行为是 0.6.2 上线事故的直接对应项，必须钉死：
    //   会话间不阻塞（修复目的）/ Open 晚到不乱序 / sid 复用不污染
    // ==============================================================

    #[test]
    /// 会话内序号按 sid 独立递增，Open 恒为该代次的 0，epoch 非 0
    fn test_session_seq_is_per_sid() {
        let enc = MuxEncoder::new(true);
        let a0 = enc.encode_frame(FrameType::Open, 7, 0, b"a");
        let a1 = enc.encode_frame(FrameType::Data, 7, 0, b"a");
        let b0 = enc.encode_frame(FrameType::Open, 9, 0, b"b");
        let seq_of = |f: &[u8]| u32::from_be_bytes([f[10], f[11], f[12], f[13]]);
        let (epoch_a0, s_a0) = (seq_of(&a0) >> 24, seq_of(&a0) & SEQ_MASK);
        let (_, s_a1) = (seq_of(&a1) >> 24, seq_of(&a1) & SEQ_MASK);
        let (epoch_b0, s_b0) = (seq_of(&b0) >> 24, seq_of(&b0) & SEQ_MASK);
        assert_ne!(epoch_a0, 0, "会话帧必须带非零 epoch");
        assert_eq!((s_a0, s_a1), (0, 1), "同会话内序号连续递增");
        assert_eq!(s_b0, 0, "另一会话的 Open 从 0 开始（序号空间互不相关）");
        assert_ne!(epoch_a0, epoch_b0, "每新建一个会话就换一代 epoch（sid 复用以同一机制天然隔离）");
        // 非会话帧（心跳）epoch 段为 0，不参与重排
        let hb = enc.encode_heartbeat();
        assert_eq!(seq_of(&hb) >> 24, 0, "控制帧不带 epoch（直投）");
    }

    #[test]
    /// 会话内乱序：超前帧只缓冲，空洞补齐后按序冲刷
    fn test_feed_reorders_within_session() {
        let enc = MuxEncoder::new(true);
        let open = enc.encode_frame(FrameType::Open, 3, 0, b"o"); // seq0
        let d1 = enc.encode_frame(FrameType::Data, 3, 0, b"1"); // seq1
        let d2 = enc.encode_frame(FrameType::Data, 3, 0, b"2"); // seq2
        let d3 = enc.encode_frame(FrameType::Data, 3, 0, b"3"); // seq3
        let mut dec = MuxDecoder::new();
        assert_eq!(dec.feed(&open).len(), 1, "Open 即时放行（会话建立）");
        assert_eq!(dec.feed(&d1)[0].payload, b"1", "连续帧即时放行");
        assert!(dec.feed(&d3).is_empty(), "d2 未到，d3 必须被缓冲而非直投（否则字节流错乱）");
        let out = dec.feed(&d2); // 补齐空洞
        let got: Vec<&str> = out.iter().map(|f| std::str::from_utf8(&f.payload).unwrap()).collect();
        assert_eq!(got, vec!["2", "3"], "补齐后按序冲刷连续段");
        assert_eq!(dec.out_of_order, 1, "乱序计数可用于证明 inorder=0 真的生效");
    }

    #[test]
    /// 核心目标：一个会话有空洞，另一个会话照常交付（跨会话队头阻塞已消除）
    fn test_feed_does_not_block_other_sessions() {
        let enc = MuxEncoder::new(true);
        // 会话 A：故意让 a2 迟到（模拟丢包）
        let a_open = enc.encode_frame(FrameType::Open, 10, 0, b"ao");
        let a1 = enc.encode_frame(FrameType::Data, 10, 0, b"a1");
        let _a2_lost = enc.encode_frame(FrameType::Data, 10, 0, b"a2");
        let a3 = enc.encode_frame(FrameType::Data, 10, 0, b"a3");
        // 会话 B：完全健康
        let b_open = enc.encode_frame(FrameType::Open, 11, 0, b"bo");
        let b1 = enc.encode_frame(FrameType::Data, 11, 0, b"b1");
        let mut dec = MuxDecoder::new();
        dec.feed(&a_open);
        dec.feed(&a1);
        assert!(dec.feed(&a3).is_empty(), "A 会话空洞 → A 的 a3 缓冲");
        // 关键断言：A 卡住期间，B 的数据必须立即交付（旧实现 inorder=1 会连坐卡死）
        assert_eq!(dec.feed(&b_open).len(), 1, "B 会话 Open 不受 A 空洞影响");
        let out = dec.feed(&b1);
        assert_eq!(out.len(), 1, "B 会话数据不受 A 会话丢包阻塞（无跨会话队头阻塞）");
        assert_eq!(out[0].payload, b"b1");
        // 心跳也必须立即放行（保活不被空洞拖住，对应隧道间歇中断的修复）
        let hb = enc.encode_heartbeat();
        assert_eq!(dec.feed(&hb).len(), 1, "控制帧绕过重排，拥塞时心跳不被卡");
    }

    #[test]
    /// Open 晚于本会话数据帧到达：先有界暂存，Open 到齐后仍按序交付
    /// （0.6.2 当时选择“直投”导致会话未建立就写入 → Rst 洪水 + 数据错乱）
    fn test_feed_buffers_data_until_open() {
        let enc = MuxEncoder::new(true);
        let open = enc.encode_frame(FrameType::Open, 21, 0, b"o"); // seq0
        let d1 = enc.encode_frame(FrameType::Data, 21, 0, b"1"); // seq1
        let d2 = enc.encode_frame(FrameType::Data, 21, 0, b"2"); // seq2
        let mut dec = MuxDecoder::new();
        // 乱序投递：数据帧抢在 Open 之前到达
        assert!(dec.feed(&d2).is_empty(), "Open 未到→暂存，绝不直投");
        assert!(dec.feed(&d1).is_empty(), "同上");
        let out = dec.feed(&open);
        let got: Vec<&str> = out.iter().map(|f| std::str::from_utf8(&f.payload).unwrap()).collect();
        assert_eq!(got, vec!["o", "1", "2"], "Open 到齐后按序放行暂存帧");
    }

    #[test]
    /// sid 复用隔离：旧会话在途残留帧不得污染新会话（epoch 判定）
    fn test_feed_sid_reuse_epoch_isolation() {
        let enc = MuxEncoder::new(true);
        // 会话 #7 第一代
        let open1 = enc.encode_frame(FrameType::Open, 7, 0, b"o1");
        let old = enc.encode_frame(FrameType::Data, 7, 0, b"OLD");
        // 第一代结束，sid=7 被新连接复用（第二代）
        let open2 = enc.encode_frame(FrameType::Open, 7, 0, b"o2");
        let fresh = enc.encode_frame(FrameType::Data, 7, 0, b"NEW");
        let mut dec = MuxDecoder::new();
        dec.feed(&open1);
        dec.feed(&open2); // 新代次建立，状态重置
        assert!(dec.feed(&old).is_empty(), "旧代次残留帧必须丢弃，不能混入新会话");
        assert_eq!(dec.stale_dropped, 1, "丢弃计数可用于线上排查");
        let out = dec.feed(&fresh);
        assert_eq!(out[0].payload, b"NEW", "新会话数据正常交付");
    }

    #[test]
    /// 重复交付（SRT 重传）只投一次，保证不向 TCP 重复写字节
    fn test_feed_drops_duplicate_frames() {
        let enc = MuxEncoder::new(true);
        let open = enc.encode_frame(FrameType::Open, 33, 0, b"o");
        let d1 = enc.encode_frame(FrameType::Data, 33, 0, b"x");
        let mut dec = MuxDecoder::new();
        dec.feed(&open);
        assert_eq!(dec.feed(&d1).len(), 1, "首次交付");
        assert!(dec.feed(&d1).is_empty(), "重复帧丢弃");
        assert_eq!(dec.stale_dropped, 1);
    }

    #[test]
    /// 回传方向（服务端→客户端）永远没有 Open 帧：首帧必须直接建基线交付
    ///（netem 有损回环实测：0.6.3 首版在这里也“等 Open”，把全部下行数据丢光 → 下载卡死）
    fn test_feed_acceptor_direction_has_no_open() {
        let enc = MuxEncoder::new_acceptor(true);
        let d0 = enc.encode_frame(FrameType::Data, 4, 0, b"a");
        let d1 = enc.encode_frame(FrameType::Data, 4, 0, b"b");
        let d2 = enc.encode_frame(FrameType::Data, 4, 0, b"c");
        let mut dec = MuxDecoder::new();
        assert_eq!(dec.feed(&d0).len(), 1, "回传方向首帧即交付（不等 Open）");
        assert!(dec.feed(&d2).is_empty(), "空洞 → 缓冲");
        let out = dec.feed(&d1);
        let got: Vec<&str> = out.iter().map(|f| std::str::from_utf8(&f.payload).unwrap()).collect();
        assert_eq!(got, vec!["b", "c"], "补齐后按序放行");
        assert_eq!(dec.stale_dropped, 0, "不该有任何丢弃（旧版此处会刷数十万条告警）");
        assert!(dec.out_of_order > 0, "乱序计数确实被记录");
    }

    #[test]
    /// 同一 sid 的两个方向各自独立编号，互不误判为陈旧/重复（=QUIC 双向 offset）
    fn test_feed_two_directions_independent() {
        let opener = MuxEncoder::new(true); // 发起方方向（客户端）
        let acceptor = MuxEncoder::new_acceptor(true); // 回传方向（服务端）
        let o_open = opener.encode_frame(FrameType::Open, 5, 0, b"open");
        let o_d1 = opener.encode_frame(FrameType::Data, 5, 0, b"up");
        let a_d0 = acceptor.encode_frame(FrameType::Data, 5, 0, b"down0");
        let a_d1 = acceptor.encode_frame(FrameType::Data, 5, 0, b"down1");
        let mut dec = MuxDecoder::new();
        assert_eq!(dec.feed(&o_open).len(), 1, "发起方方向以 Open 起点");
        assert_eq!(dec.feed(&o_d1)[0].payload, b"up");
        // 回传方向从自己的 0 号开始，不能被发起方方向的序号当成“重复/陈旧”丢弃
        assert_eq!(dec.feed(&a_d0)[0].payload, b"down0", "回传方向首帧不被误判");
        assert_eq!(dec.feed(&a_d1)[0].payload, b"down1");
        assert_eq!(dec.stale_dropped, 0, "两方向序号空间独立，不应有丢弃");
    }
}
