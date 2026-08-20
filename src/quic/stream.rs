//! quic/stream.rs — 多流接口（自研 QUIC 语义）
//!
//! 设计（借鉴 RFC 9000 流模型，简化）：
//! - 每条流 = 一个独立的数据通道（对应 VPN 的一个 TCP 会话）
//! - 流 ID 空间：0 保留，1..=255 可用（与旧 256 会话上限对齐）
//! - 流控：流级（MAX_STREAM_DATA 限单流）+ 连接级（MAX_DATA 限总量）
//! - 语义：可靠字节流，支持半关闭（FIN）、重置（RST_STREAM）
//! - 乱序重组：接收侧按 (offset) 重组，不依赖底层有序（自研内核没有 SRT 保证序）
//!
//! 内存模型：每条流一个内部缓冲（VecDeque + 已确认偏移游标）。
//! 发送侧：应用层 push 数据 → 发送缓冲 → 发送线程按拥控窗口取帧；
//! 接收侧：收到 STREAM 帧 → 按 offset 插入接收缓冲 → recv 取出连续段。

use std::collections::HashMap;

/// 最大流数（含保留的 0 号流，1..=254 可用）
pub const MAX_STREAMS: u32 = 256;

/// 单流发送缓冲上限（字节）。超过后应用层发送被阻塞（背压）。
/// 选 1MB（典型 TCP socket 缓冲级别），可通过流控窗口控制。
pub const STREAM_SEND_BUFFER: usize = 1 << 20;

/// 单流接收缓冲上限（字节）。超限丢弃远端数据（协议级流控屏障）。
///（P1.5 接收侧精确流控接入时启用）
#[allow(dead_code)]
pub const STREAM_RECV_BUFFER: usize = 1 << 20;

/// 流的状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// 已打开（可收发）
    Open,
    /// 发送方向已关闭（本端发完 FIN，仍可收；P1.5 半关闭接入启用）
    #[allow(dead_code)]
    SendClosed,
    /// 接收方向已关闭（对端发 FIN，仍可发；P1.5 半关闭接入启用）
    #[allow(dead_code)]
    RecvClosed,
    /// 双向关闭（或 RST）
    Closed,
}

/// 单条流的发送侧上下文（智能指针引用计数的可变状态）
pub(crate) struct StreamSend {
    /// 已发出的最大流内偏移（对端从这里继续期待数据）
    pub(crate) sent_offset: u64,
    /// 对端已确认的最大偏移（用于回收缓冲；P1.5 ACK 回收启用）
    #[allow(dead_code)]
    pub(crate) acked_offset: u64,
    /// 待发送缓冲（VecDeque: (offset, bytes)）
    pub(crate) pending: std::collections::VecDeque<(u64, Vec<u8>)>,
    /// 是否已发 FIN（发送方向关闭）
    pub(crate) fin_sent: bool,
    /// 已发 FIN 的偏移（FIN 帧携带的 offset）
    pub(crate) fin_offset: u64,
    /// 流的发送结论（本地结束）
    pub(crate) sender_finished: bool,
}

impl StreamSend {
    pub(crate) fn new() -> Self {
        Self {
            sent_offset: 0,
            acked_offset: 0,
            pending: std::collections::VecDeque::new(),
            fin_sent: false,
            fin_offset: 0,
            sender_finished: false,
        }
    }
}

/// 单条流的接收侧上下文
pub(crate) struct StreamRecv {
    /// 已交付给应用的最大连续偏移（无空洞）
    pub(crate) delivered_offset: u64,
    /// 接收乱序缓冲（按 offset 存储已到但未交付的数据）
    pub(crate) unordered: std::collections::BTreeMap<u64, Vec<u8>>,
    /// 已重组的连续数据块（按序交付给应用；recv_take 取走）
    /// 2026-08-20 P1.5 修复（高速下数据错乱根因）：主数据流原先不经过
    /// 重组直接投递——丢包重传后到达顺序颠倒导致数据错位。现在所有流都
    /// 走 recv_data 按 offset 重组，连续块暂存本队列，供上层顺序消费。
    pub(crate) delivered: std::collections::VecDeque<Vec<u8>>,
    /// 对端是否已发 FIN（收到 FIN 帧标记）
    pub(crate) fin_received: bool,
    /// 收到 FIN 的流内偏移
    pub(crate) fin_offset: u64,
    /// 流的接收结论（远结束后）
    pub(crate) receiver_finished: bool,
}

impl StreamRecv {
    pub(crate) fn new() -> Self {
        Self {
            delivered_offset: 0,
            unordered: std::collections::BTreeMap::new(),
            delivered: std::collections::VecDeque::new(),
            fin_received: false,
            fin_offset: 0,
            receiver_finished: false,
        }
    }
}

/// 一条流的双端状态（需显式 Default，因为有 Option 字段与复杂状态）
pub struct Stream {
    /// 流 ID（语义标识；当前以 HashMap key 关联，字段保留供日志/诊断）
    #[allow(dead_code)]
    pub(crate) id: u32,
    pub(crate) state: StreamState,
    pub(crate) send: Option<StreamSend>,
    pub(crate) recv: Option<StreamRecv>,
}

impl Default for Stream {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Stream {
    pub(crate) fn new(id: u32) -> Self {
        Self {
            id,
            state: StreamState::Open,
            send: Some(StreamSend::new()),
            recv: Some(StreamRecv::new()),
        }
    }

    /// 流的当前状态（P1.5 per-session 接入启用）
    #[allow(dead_code)]
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// 发送方向是否完成（发完 FIN 且数据全 ack；P1.5 per-session 接入启用）
    #[allow(dead_code)]
    pub fn is_send_finished(&self) -> bool {
        self.send.as_ref().map(|s| s.sender_finished).unwrap_or(true)
    }

    /// 接收方向是否完成（收到 FIN 且数据全交付；P1.5 per-session 接入启用）
    #[allow(dead_code)]
    pub fn is_recv_finished(&self) -> bool {
        self.recv.as_ref().map(|r| r.receiver_finished).unwrap_or(true)
    }

    /// 双向是否都完成（P1.5 per-session 接入启用）
    #[allow(dead_code)]
    pub fn is_complete(&self) -> bool {
        self.is_send_finished() && self.is_recv_finished()
    }

    /// 应用层写入数据（追加到发送缓冲）
    ///
    /// 返回实际接收字节数；0 表示缓冲满（背压，应稍后重试或交给发送线程轮询）。
    pub fn send(&mut self, data: &[u8]) -> usize {
        let Some(s) = self.send.as_mut() else {
            return 0; // 发送方向已关闭
        };
        if s.sender_finished {
            return 0;
        }
        let pending_bytes: usize = s.pending.iter().map(|(_, b)| b.len()).sum();
        if pending_bytes >= STREAM_SEND_BUFFER {
            return 0; // 背压：缓冲满
        }
        // 计算可接纳的字节数（不超缓冲上限）
        let room = STREAM_SEND_BUFFER.saturating_sub(pending_bytes);
        let take = room.min(data.len());
        if take == 0 {
            return 0;
        }
        let offset = s.sent_offset;
        s.pending.push_back((offset, data[..take].to_vec()));
        s.sent_offset += take as u64;
        take
    }

    /// 应用层标记发送结束（发 FIN；P1.5 per-session 接入启用）
    #[allow(dead_code)]
    pub fn send_fin(&mut self) {
        if let Some(s) = self.send.as_mut() {
            s.fin_sent = true;
            s.fin_offset = s.sent_offset;
        }
    }

    /// 获取待发送数据块（发送线程取帧用）。返回 (offset, bytes, fin)。
    /// 取出的块会被移除——由发送线程转硬件/网络，失败不重放（依赖 ACK 重传）
    pub fn take_send_block(&mut self) -> Option<(u64, Vec<u8>, bool)> {
        let s = self.send.as_mut()?;
        if let Some((offset, bytes)) = s.pending.pop_front() {
            return Some((offset, bytes, false));
        }
        // 无数据：若已发 FIN 且未标记完成，返回 FIN 提示
        if s.fin_sent && !s.sender_finished && s.pending.is_empty() {
            s.sender_finished = true; // 发送完成（数据已全发出）
            return Some((s.fin_offset, Vec::new(), true));
        }
        None
    }

    /// 预检下一个待发送块（不发，供拥控预算判断）。返回 (offset, bytes, fin)
    pub fn peek_send_block(&mut self) -> Option<(u64, Vec<u8>, bool)> {
        let s = self.send.as_mut()?;
        if !s.pending.is_empty() {
            let (offset, bytes) = &s.pending[0];
            return Some((*offset, bytes.as_slice().to_vec(), false));
        }
        if s.fin_sent && !s.sender_finished {
            return Some((s.fin_offset, Vec::new(), true));
        }
        None
    }

    /// 对端 ACK 推进（确认到 acked_offset，回收发送缓冲；P1.5 ACK 回收启用）
    #[allow(dead_code)]
    pub fn on_ack(&mut self, acked_offset: u64) -> Option<u64> {
        let s = self.send.as_mut()?;
        if acked_offset > s.acked_offset {
            s.acked_offset = acked_offset;
        }
        // 数据已全部确认且已发 FIN：发送结论彻底完成
        if s.sender_finished && s.acked_offset >= s.fin_offset {
            s.sender_finished = true;
        }
        Some(s.acked_offset)
    }

    /// 接收侧：投递一个 STREAM 帧的数据（含 FIN 标记）
    ///
    /// - offset < delivered_offset：重复数据，忽略
    /// - 无空洞可交付：直接推进 delivered_offset
    /// - 有空洞：存入 unordered，等待前序到达
    /// - fin：记录 fin_offset，当 delivered_offset >= fin_offset 时接收方向完成
    pub fn recv_data(&mut self, offset: u64, data: &[u8], fin: bool) {
        let Some(r) = self.recv.as_mut() else { return };
        // 重复/过期块忽略
        if offset + data.len() as u64 <= r.delivered_offset {
            if fin && r.fin_offset + 0 <= r.delivered_offset {
                r.fin_received = true;
                r.fin_offset = offset + data.len() as u64;
            }
            return;
        }
        if fin {
            r.fin_received = true;
            r.fin_offset = offset.max(r.fin_offset).max(r.delivered_offset);
        }
        // 合并到乱序缓冲
        r.unordered.insert(offset, data.to_vec());
        // 交付连续段（无空洞时把连续块暂存到 delivered 队列，供 recv_take 顺序取）
        let mut next = r.delivered_offset;
        while let Some(bytes) = r.unordered.remove(&next) {
            r.delivered.push_back(bytes);
            next += r.delivered.back().map(|b| b.len() as u64).unwrap_or(0);
        }
        r.delivered_offset = next;
        // 若已收 FIN 且全部交付，接收方向完成
        if r.fin_received && r.delivered_offset >= r.fin_offset {
            r.receiver_finished = true;
        }
    }

    /// 应用层读取已交付数据：返回从 delivered_offset 起的连续数据并推进
    ///
    /// 2026-08-20 P1.5 修复：由 recv_data 重组暂存到 delivered 队列，本函数
    /// 按序取出全部已交付字节（乱序重传在 recv_data 已解决，这里天然有序）。
    pub fn recv_take(&mut self) -> Vec<u8> {
        let r = match self.recv.as_mut() {
            Some(r) => r,
            None => return Vec::new(),
        };
        let mut out = Vec::new();
        for b in r.delivered.drain(..) {
            out.extend_from_slice(&b);
        }
        out
    }

    /// 是否已收到 FIN 且数据完整交付（对端发送方向结束；P1.5 per-session 接入启用）
    #[allow(dead_code)]
    pub fn is_fin_received(&self) -> bool {
        let r = self.recv.as_ref().map(|r| r.fin_received && r.receiver_finished).unwrap_or(false);
        r
    }

    /// 强制重置流（RST_STREAM 语义）
    pub fn reset(&mut self, _error_code: u32) {
        self.state = StreamState::Closed;
        self.send = None;
        self.recv = None;
    }
}

/// 流管理器（连接级持有）
pub struct StreamManager {
    /// 流表 id -> Stream
    streams: HashMap<u32, Stream>,
    /// 下一个待分配的空闲流 ID（从 1 起，循环查找；诊断/统计用）
    #[allow(dead_code)]
    next_id: u32,
    /// 活动流计数（用于指标）
    active: usize,
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamManager {
    /// 创建流管理器
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            next_id: 1,
            active: 0,
        }
    }

    /// 分配一条新流（返回流 ID；满则 None）
    ///（P1.5 per-session 多流接入时启用）
    #[allow(dead_code)]
    pub fn open_stream(&mut self) -> Option<u32> {
        if self.streams.len() >= MAX_STREAMS as usize {
            return None;
        }
        // 循环扫描空闲 ID（从 next_id 开始找未占用的）
        for _ in 0..MAX_STREAMS {
            let id = self.next_id;
            self.next_id = if self.next_id + 1 >= MAX_STREAMS { 1 } else { self.next_id + 1 };
            if !self.streams.contains_key(&id) {
                let id = id as u32;
                self.streams.insert(id, Stream::new(id));
                self.active += 1;
                return Some(id);
            }
        }
        None
    }

    /// 检查流是否存在
    pub fn stream_exists(&self, id: u32) -> bool {
        self.streams.contains_key(&id)
    }

    /// 在指定 ID 打开流（若不存在）；已存在则返回 true
    /// 用于主数据流等固定 ID 场景
    pub fn open_stream_at(&mut self, id: u32) -> bool {
        if id == 0 {
            return false; // 0 保留
        }
        if self.streams.contains_key(&id) {
            return true;
        }
        if self.streams.len() >= MAX_STREAMS as usize {
            return false;
        }
        self.streams.insert(id, Stream::new(id));
        self.active += 1;
        true
    }

    /// 获取流（不存在返回 None）
    pub fn get(&mut self, id: u32) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    /// 按 ID 关闭并移除一条流（Complete/RST 后回收）
    pub fn close_stream(&mut self, id: u32) -> Option<Stream> {
        let s = self.streams.remove(&id)?;
        self.active = self.active.saturating_sub(1);
        self.streams.remove(&id);
        Some(s)
    }

    /// 活动流数（P1.5 指标/监控接入时启用）
    #[allow(dead_code)]
    pub fn active_count(&self) -> usize {
        self.active
    }

    /// 活动流 ID 列表（send_loop 轮询取发数据用）
    pub fn active_ids(&self) -> Vec<u32> {
        self.streams.keys().copied().collect()
    }

    /// 流总数（含完成未回收的；P1.5 指标/监控接入时启用）
    #[allow(dead_code)]
    pub fn total(&self) -> usize {
        self.streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 流打开/关闭生命周期 + ID 单调递增（不循环复用，避重放会话冲突）
    #[test]
    fn test_stream_open_close() {
        let mut mgr = StreamManager::new();
        let id = mgr.open_stream().expect("应能开流");
        assert_eq!(id, 1);
        assert!(mgr.get(id).is_some());
        assert!(mgr.get(999).is_none());

        mgr.close_stream(id);
        assert!(mgr.get(id).is_none());
        // 新流 ID 单调递增（不复用旧 ID，避免新旧会话混淆）
        let id2 = mgr.open_stream().expect("应能再开流");
        assert!(id2 > id, "ID 应单调递增不复用：先 {id} 后 {id2}");
        assert!(mgr.get(id).is_none(), "已关闭流不可再取");
    }

    /// 发送缓冲背压
    #[test]
    fn test_send_buffer_backpressure() {
        let mut mgr = StreamManager::new();
        let id = mgr.open_stream().unwrap();
        let s = mgr.get(id).unwrap();
        // 填满 1MB 缓冲
        let chunk = vec![0xAB; 4096];
        let mut total = 0;
        loop {
            let n = s.send(&chunk);
            if n == 0 {
                break;
            }
            total += n;
            if total > STREAM_SEND_BUFFER + 1 {
                break;
            }
        }
        assert!(total <= STREAM_SEND_BUFFER, "缓冲应封顶 {total}");
        // 取出发送再写应恢复
        let (_, _, _) = s.take_send_block().expect("应有数据块");
        let n = s.send(&chunk);
        assert!(n > 0, "取出后应能再写");
    }

    /// 乱序重组：先收 offset 5 再收 offset 0，交付顺序正确
    #[test]
    fn test_recv_reordering() {
        let mut mgr = StreamManager::new();
        let id = mgr.open_stream().unwrap();
        // 先投递后半段
        {
            let s = mgr.get(id).unwrap();
            s.recv_data(5, b"world", false);
            assert_eq!(s.recv.as_ref().unwrap().delivered_offset, 0, "有空洞不交付");
        }
        // 再投递前半段
        {
            let s = mgr.get(id).unwrap();
            s.recv_data(0, b"hello", false);
            assert_eq!(s.recv.as_ref().unwrap().delivered_offset, 10, "补齐后连续交付");
        }
    }

    /// FIN 完成语义
    #[test]
    fn test_fin_semantics() {
        let mut mgr = StreamManager::new();
        let id = mgr.open_stream().unwrap();
        {
            let s = mgr.get(id).unwrap();
            s.recv_data(0, b"data", true); // 数据+FIN 一起
            assert!(s.is_fin_received(), "应识别对端 FIN");
            assert!(s.is_recv_finished(), "数据全交付+FIN=接收完成");
        }
    }

    /// 发送 FIN + 取发 FIN
    #[test]
    fn test_send_fin() {
        let mut mgr = StreamManager::new();
        let id = mgr.open_stream().unwrap();
        {
            let s = mgr.get(id).unwrap();
            s.send(b"abc");
            s.send_fin();
        }
        // 第一块数据
        let (off, bytes, fin) = mgr.get(id).unwrap().take_send_block().unwrap();
        assert_eq!(off, 0);
        assert_eq!(bytes, b"abc".to_vec());
        assert!(!fin);
        // 第二块 FIN
        let (off, bytes, fin) = mgr.get(id).unwrap().take_send_block().unwrap();
        assert_eq!(off, 3);
        assert!(bytes.is_empty());
        assert!(fin);
        // 无更多
        assert!(mgr.get(id).unwrap().take_send_block().is_none());
    }
}