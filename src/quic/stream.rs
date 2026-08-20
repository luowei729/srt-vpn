//! quic/stream.rs - 多流缓冲与乱序重组 v2
//!
//! 2026-08-20 v2 重写：v1 的 StreamRecv 在 recv_data 里丢弃已交付数据、
//! recv_take 是空壳、主流绕过重组直接投递（高速乱序数据错乱根因之一）。
//! v2 语义：
//! - 每条流 = 可靠有序字节流（发送侧缓冲 + 接收侧 offset 重组）
//! - **包级有序由传输层保证**（包号 ACK + 重传），流内 offset 重组兜底
//!   （同一流的 STREAM 帧可能乱序到达，比如重传包晚到）
//! - 接收侧 delivered 队列：重组完成即入队，上层按序取走
//! - FIN 语义：fin_offset 记录流结束位置，全部交付后 receiver_finished
//!
//! 内存模型：
//! - 发送缓冲上限 STREAM_SEND_BUFFER（1MB），满则背压（send 返回 0）
//! - 接收 unordered 上限 RECV_UNORDERED_MAX，超限丢弃最旧乱序块（依赖重传）

use std::collections::{BTreeMap, VecDeque};

/// 最大流数（含保留的 0 号流）
pub const MAX_STREAMS: u32 = 256;

/// 单流发送缓冲上限（字节）。超过后应用层发送被阻塞（背压）。
pub const STREAM_SEND_BUFFER: usize = 1 << 20;

/// 接收乱序缓冲上限（字节）。超限丢最旧（依赖重传恢复）。
pub const RECV_UNORDERED_MAX: usize = 4 << 20;

/// 流状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// 打开（可收发）
    Open,
    /// 已关闭（FIN 交付或 RST；P1.5 状态机扩展时启用）
    #[allow(dead_code)]
    Closed,
}

/// 单条流的发送侧
pub(crate) struct StreamSend {
    /// 下一个待发块的流内偏移（发送游标）
    next_offset: u64,
    /// 待发送队列 (offset, bytes)
    pending: VecDeque<(u64, Vec<u8>)>,
    /// 已入队总字节（背压判断）
    queued_bytes: usize,
    /// 是否已标记 FIN（发送方向关闭）
    fin_sent: bool,
    /// FIN 哨兵块是否已发（防止重复发 FIN）
    fin_block_sent: bool,
    /// FIN 的流内偏移
    fin_offset: u64,
}

impl StreamSend {
    fn new() -> Self {
        Self {
            next_offset: 0,
            pending: VecDeque::new(),
            queued_bytes: 0,
            fin_sent: false,
            fin_block_sent: false,
            fin_offset: 0,
        }
    }

    /// 追加发送数据（返回接受字节数；0 = 背压满）
    ///
    /// 2026-08-20 v2 关键修复：**原子语义**--缓冲空间不足以容纳整块时
    /// 返回 0 等待重试，绝不部分写入。原因：上层 Mux 按"每块 = 一帧"
    /// 解码（take_delivered_blocks 保持块边界），部分写入会把一个
    /// Mux 帧拆成两个流块，接收侧帧头与 payload 分离 -> "帧长度超界"
    /// -> 会话数据错乱。帧最大 1316B vs 缓冲 1MB，等待代价仅毫秒级。
    fn send(&mut self, data: &[u8]) -> usize {
        if self.fin_sent || data.is_empty() {
            return 0;
        }
        // 原子判定：整块能放下才接受（防部分写入破坏块边界）
        if self.queued_bytes + data.len() > STREAM_SEND_BUFFER {
            return 0;
        }
        let offset = self.next_offset;
        self.pending.push_back((offset, data.to_vec()));
        self.next_offset += data.len() as u64;
        self.queued_bytes += data.len();
        data.len()
    }

    /// 标记发送结束（FIN；P1.5 连接关闭时序接入启用）
    #[allow(dead_code)]
    fn send_fin(&mut self) {
        if !self.fin_sent {
            self.fin_sent = true;
            self.fin_offset = self.next_offset;
        }
    }

    /// 取下一待发块（移除）。返回 (offset, bytes, fin)。
    /// FIN 作为末尾哨兵块返回（bytes 空 + fin=true，仅一次）。
    fn take_block(&mut self) -> Option<(u64, Vec<u8>, bool)> {
        if let Some((offset, bytes)) = self.pending.pop_front() {
            self.queued_bytes -= bytes.len();
            return Some((offset, bytes, false));
        }
        // FIN 哨兵：数据发完后发一次（独立标志防重复，避免 v1 的
        // next_offset > fin_offset 恒假 bug）
        if self.fin_sent && !self.fin_block_sent {
            self.fin_block_sent = true;
            return Some((self.fin_offset, Vec::new(), true));
        }
        None
    }

    /// 窥视下一数据块大小（不移除；0 = 只有 FIN 哨兵或空）。
    ///
    /// 2026-08-20 v2 关键修复配套接口：send_loop 必须先窥视再取块——
    /// 旧逻辑先 take_block（块已移出队列）后发现预算不足直接 break，
    /// 块被静默丢弃且无重传依据（tracker 未记账），流内出现永久空洞，
    /// 接收方 delivered_offset 卡住、整条流死锁（10MB 下载卡 16KB 根因，
    /// 空洞恰好 10×1316 = 慢启动 ramp 期预算残值 < 单块的轮次累计）。
    pub(crate) fn peek_block_len(&self) -> usize {
        self.pending.front().map(|(_, b)| b.len()).unwrap_or(0)
    }

    /// 是否还有待发数据/FIN
    fn has_pending(&self) -> bool {
        !self.pending.is_empty() || (self.fin_sent && !self.fin_block_sent)
    }
}

/// 单条流的接收侧
pub(crate) struct StreamRecv {
    /// 已交付的最大连续偏移（无空洞）
    delivered_offset: u64,
    /// 乱序缓冲（offset -> bytes）
    unordered: BTreeMap<u64, Vec<u8>>,
    /// 乱序缓冲总字节（上限控制）
    unordered_bytes: usize,
    /// 已重组待上层取走的数据块队列
    delivered: VecDeque<Vec<u8>>,
    /// 是否已收 FIN（当前会话的发送方向结束）
    fin_received: bool,
    /// FIN 的流内偏移
    fin_offset: u64,
    /// FIN 是否已通知上层（防重复事件；单主流多会话复用场景关键）
    fin_notified: bool,
}

impl StreamRecv {
    fn new() -> Self {
        Self {
            delivered_offset: 0,
            unordered: BTreeMap::new(),
            unordered_bytes: 0,
            delivered: VecDeque::new(),
            fin_received: false,
            fin_offset: 0,
            fin_notified: false,
        }
    }

    /// 投递一个 STREAM 帧的数据（offset 幂等：重复/过期忽略）
    fn recv_data(&mut self, offset: u64, data: &[u8], fin: bool) {
        if fin {
            self.fin_received = true;
            self.fin_offset = self.fin_offset.max(offset + data.len() as u64);
        }
        // 重复/过期：整块都在已交付边界之前
        if offset + data.len() as u64 <= self.delivered_offset {
            return;
        }
        // 同 offset 重复到达（重传；尚未交付）：覆盖防重复计数
        if let Some(old) = self.unordered.get(&offset) {
            if old.len() >= data.len() {
                return; // 已有等长或更长块，忽略
            }
            self.unordered_bytes -= old.len();
        }
        self.unordered.insert(offset, data.to_vec());
        self.unordered_bytes += data.len();
        // 乱序缓冲超限：丢最旧（发送方 RTO 会重传）
        while self.unordered_bytes > RECV_UNORDERED_MAX {
            if let Some(first_key) = self.unordered.keys().next().copied() {
                if first_key >= self.delivered_offset {
                    break; // 不能丢空洞头（那是队头，丢了卡死）
                }
                if let Some(v) = self.unordered.remove(&first_key) {
                    self.unordered_bytes -= v.len();
                }
            } else {
                break;
            }
        }
        // 重组：从 delivered_offset 起连续取块
        while let Some(bytes) = self.unordered.remove(&self.delivered_offset) {
            self.unordered_bytes -= bytes.len();
            self.delivered_offset += bytes.len() as u64;
            self.delivered.push_back(bytes);
        }
    }

    /// 取走全部已重组数据块（保持块边界；上层每块一条消息）
    ///
    /// 2026-08-20 v2 关键修复：不能拼接成单个 Vec！发送侧 send_msg 每条
    /// 应用消息（Mux 帧）单独入队，块边界 = 消息边界全程保持。拼接会
    /// 破坏帧边界，上层 decode_frame 只解第一帧其余丢弃（实测 curl 只
    /// 收到 16KB 根因）。
    fn take_delivered_blocks(&mut self) -> Vec<Vec<u8>> {
        self.delivered.drain(..).collect()
    }

    /// 接收是否完成（FIN 且全交付）且未通知过（只通知一次）
    fn is_finished(&mut self) -> bool {
        if self.fin_notified {
            return false;
        }
        if self.fin_received && self.delivered_offset >= self.fin_offset {
            self.fin_notified = true;
            return true;
        }
        false
    }
}

/// 一条流（收发双上下文）
pub struct Stream {
    state: StreamState,
    send: StreamSend,
    recv: StreamRecv,
}

impl Stream {
    fn new() -> Self {
        Self {
            state: StreamState::Open,
            send: StreamSend::new(),
            recv: StreamRecv::new(),
        }
    }

    /// 追加发送数据
    pub fn send(&mut self, data: &[u8]) -> usize {
        self.send.send(data)
    }

    /// 标记发送结束（FIN；P1.5 连接关闭时序接入启用）
    #[allow(dead_code)]
    pub fn send_fin(&mut self) {
        self.send.send_fin();
    }

    /// 取下一待发块
    pub fn take_block(&mut self) -> Option<(u64, Vec<u8>, bool)> {
        self.send.take_block()
    }

    /// 窥视下一数据块大小（不移除；send_loop 预算判断用）
    pub fn peek_block_len(&self) -> usize {
        self.send.peek_block_len()
    }

    /// 是否还有待发数据（P1.5 监控接入时启用）
    #[allow(dead_code)]
    pub fn has_pending(&self) -> bool {
        self.send.has_pending()
    }

    /// 投递接收数据（offset 幂等）
    pub fn recv_data(&mut self, offset: u64, data: &[u8], fin: bool) {
        self.recv.recv_data(offset, data, fin);
    }

    /// 取走全部已重组数据块（保持块边界；每块 = 一条应用消息）
    pub fn take_delivered_blocks(&mut self) -> Vec<Vec<u8>> {
        self.recv.take_delivered_blocks()
    }

    /// 是否有待交付数据
    pub fn has_delivered(&self) -> bool {
        !self.recv.delivered.is_empty()
    }

    /// 接收是否完成（FIN 且全交付；只通知一次，防重复事件）
    pub fn is_finished(&mut self) -> bool {
        self.recv.is_finished()
    }

    /// 强制关闭（RST；P1.5 流级复位接入时启用）
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.state = StreamState::Closed;
    }
}

/// 流管理器（连接级）
pub struct StreamManager {
    streams: std::collections::HashMap<u32, Stream>,
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            streams: std::collections::HashMap::new(),
        }
    }

    /// 打开流（已存在则无操作）
    pub fn open(&mut self, id: u32) -> bool {
        if id == 0 || self.streams.len() >= MAX_STREAMS as usize {
            return false;
        }
        self.streams.entry(id).or_insert_with(Stream::new);
        true
    }

    /// 流是否存在
    pub fn exists(&self, id: u32) -> bool {
        self.streams.contains_key(&id)
    }

    /// 获取流（可变）
    pub fn get(&mut self, id: u32) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    /// 移除流（完成/重置后回收）
    pub fn remove(&mut self, id: u32) {
        self.streams.remove(&id);
    }

    /// 活动流 ID 列表（发送循环轮询用）
    pub fn active_ids(&self) -> Vec<u32> {
        self.streams.keys().copied().collect()
    }

    /// 是否存在有待发数据的流（P1.5 监控接入时启用）
    #[allow(dead_code)]
    pub fn any_pending(&self) -> bool {
        self.streams.values().any(|s| s.has_pending())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 发送缓冲背压
    #[test]
    fn test_send_backpressure() {
        let mut s = Stream::new();
        let chunk = vec![0xAB; 4096];
        let mut total = 0;
        loop {
            let n = s.send(&chunk);
            if n == 0 {
                break;
            }
            total += n;
        }
        assert!(total >= STREAM_SEND_BUFFER - 4096, "应能灌到接近上限: {total}");
        assert!(total <= STREAM_SEND_BUFFER, "不应超上限: {total}");
    }

    /// 有序接收：顺序投递全交付（块边界保持）
    #[test]
    fn test_recv_ordered() {
        let mut s = Stream::new();
        s.recv_data(0, b"hello ", false);
        s.recv_data(6, b"world", false);
        let blocks = s.take_delivered_blocks();
        assert_eq!(blocks, vec![b"hello ".to_vec(), b"world".to_vec()]);
        assert!(!s.has_delivered());
    }

    /// 乱序接收：后到先投，重组后块序交付
    #[test]
    fn test_recv_reordering() {
        let mut s = Stream::new();
        s.recv_data(6, b"world", false);
        assert!(s.take_delivered_blocks().is_empty(), "有空洞不交付");
        s.recv_data(0, b"hello ", false);
        let blocks = s.take_delivered_blocks();
        assert_eq!(blocks.len(), 2, "两块独立交付（保持块边界）");
        assert_eq!(blocks[0], b"hello ");
        assert_eq!(blocks[1], b"world");
    }

    /// 重复包幂等（重传场景）
    #[test]
    fn test_recv_duplicate() {
        let mut s = Stream::new();
        s.recv_data(0, b"abc", false);
        assert_eq!(s.take_delivered_blocks(), vec![b"abc".to_vec()]);
        s.recv_data(0, b"abc", false); // 重传重复
        assert!(s.take_delivered_blocks().is_empty(), "重复包不重复交付");
    }

    /// FIN 语义：数据 + FIN 全交付后完成
    #[test]
    fn test_fin_completion() {
        let mut s = Stream::new();
        s.recv_data(0, b"data", true); // 带 FIN，fin_offset=4
        assert!(s.is_finished(), "数据+FIN 全交付应完成");
        assert_eq!(s.take_delivered_blocks(), vec![b"data".to_vec()]);
    }

    /// FIN 分离到达（数据后 FIN 帧）
    #[test]
    fn test_fin_separate() {
        let mut s = Stream::new();
        s.recv_data(0, b"abc", false);
        s.recv_data(3, b"", true); // 空 FIN 帧 offset=3
        assert!(s.is_finished());
    }

    /// 发送块迭代 + FIN 哨兵
    #[test]
    fn test_take_block_with_fin() {
        let mut s = Stream::new();
        s.send(b"abc");
        s.send_fin();
        let (off1, b1, f1) = s.take_block().unwrap();
        assert_eq!((off1, b1.as_slice(), f1), (0, b"abc".as_slice(), false));
        let (off2, b2, f2) = s.take_block().unwrap();
        assert_eq!((off2, b2.len(), f2), (3, 0, true), "FIN 哨兵块");
        assert!(s.take_block().is_none(), "FIN 只发一次");
    }

    /// StreamManager 基本操作
    #[test]
    fn test_stream_manager() {
        let mut m = StreamManager::new();
        assert!(m.open(1));
        assert!(m.exists(1));
        assert!(!m.open(0), "0 号保留");
        assert!(m.get(1).is_some());
        m.remove(1);
        assert!(!m.exists(1));
    }
}
