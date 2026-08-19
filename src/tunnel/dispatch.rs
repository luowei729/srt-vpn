//! tunnel/dispatch.rs — 会话分发器（客户端/服务端共享）
//!
//! 设计决策（Q7/Q20）：
//! - 单 SRT 连接承载多路会话，每会话独立接收通道
//! - 数据流：
//!   发送侧：应用数据 → 复用层 Data 帧 → TS 封装 → SRT 发送
//!   接收侧：SRT 接收 → TS 解码 → 复用层帧 → 按会话 ID 路由到会话通道
//! - 会话生命周期：allocate → 发送 Open 帧 → 双向转发 → Close/Fin
//!
//! 线程模型：
//! - 每个会话一个 tokio::sync::mpsc 接收通道
//! - 隧道接收循环（recv_loop）把 Data 帧按 session_id 路由到对应通道
//! - 会话处理任务（SOCKS5 连接 / 服务器转发）从自己的通道读数据

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::srt::connection::SrtConnection;
use crate::tunnel::multiplex::{Frame, MuxEncoder, FRAME_DATA_MAX};
use crate::tunnel::MAX_SESSIONS;
use crate::tunnel::FrameType;

// FRAME_DATA_MAX 复用 multiplex.rs 的定义（SRT 原生大包 1301B，2026-08-19 移除 TS 伪装）。
// 注意：不要在本文件重复定义旧值（曾错误地保留 169，导致分片仍是 169B 小包、
// 全双工吞吐塌陷）。

/// 会话通道事件（隧道接收循环 → 会话处理任务）
///
/// 2026-08-19 审查修复（B2 半关闭语义）：
/// 此前通道只传 `Vec<u8>` 数据，导致 FIN/Close 控制信号只能由接收循环直接
/// `registry.remove(sid)` 处理——这在收到 FIN 时立即删会话，破坏了"半关闭
/// （单向 FIN 传播，仍可收剩余数据）"语义（尾部数据被丢弃）。
/// 现改为事件类型：Data 传数据 / Fin 通知对端单向关闭 / Close 通知对端完全关闭，
/// 由会话任务自己决定何时真正结束（双向 FIN 后 Close），保证剩余数据不丢。
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// 数据帧（对端发来的应用数据）
    Data(Vec<u8>),
    /// 对端半关闭（单向 FIN：对端不再发数据，但本端仍可向对端发）
    Fin,
    /// 对端完全关闭会话
    Close,
}

/// 会话注册表（隧道接收循环与各会话处理任务共享）
#[derive(Clone)]
pub struct SessionRegistry {
    /// 会话 ID → 接收通道发送端（会话处理任务消费）
    sessions: Arc<std::sync::Mutex<HashMap<u16, mpsc::UnboundedSender<SessionEvent>>>>,
    /// 下一个会话 ID（递增分配）
    next_id: Arc<std::sync::atomic::AtomicU32>,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    /// 创建会话注册表
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            next_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        }
    }

    /// 分配新会话，返回 (会话 ID, 接收通道接收端)
    /// 接收端用于会话处理任务读取来自隧道的数据/控制信号
    ///
    /// 2026-08-19 审查修复（F4/F5）：
    /// - 增加会话上限校验（MAX_SESSIONS=256）：超限返回 None（此前无上限可无限分配，
    ///   配合无超时的会话会耗尽内存）
    /// - 修复 ID 分配边界：改用 u32 递增 + 显式 1..=255 映射（原 `id & 0xFF`
    ///   在 id=256 时会产生 0=保留控制通道 ID），ID 满无法找到空闲时返回 None 不再死循环
    /// - 接入会话指标（F2）：分配时更新 active_sessions / total_sessions
    pub fn allocate(&self) -> Option<(u16, mpsc::UnboundedReceiver<SessionEvent>)> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut map = self.sessions.lock().unwrap();
        // 会话上限校验：已分配会话数 ≥ 上限则拒绝
        if map.len() >= MAX_SESSIONS - 1 {
            return None;
        }
        // 显式 1..=255 循环寻找空闲 ID（0 保留给控制通道）
        for _ in 0..MAX_SESSIONS {
            let raw = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let id = (raw % (MAX_SESSIONS as u32)) as u16;
            if id == 0 {
                continue; // 保留控制通道
            }
            if !map.contains_key(&id) {
                map.insert(id, tx);
                let m = crate::metrics::metrics();
                m.active_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                m.total_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Some((id, rx));
            }
        }
        None
    }

    /// 按指定会话 ID 注册接收通道（服务端转发用）
    ///
    /// 服务端在收到客户端 Open 帧时，会话 ID 已由客户端决定，
    /// 转发任务需要按该 ID 注册自己的接收通道。
    /// 返回 None 表示 ID 已被占用（0 保留或重复）。
    ///
    /// 2026-08-19 审查修复（F2 指标一致性）：与 allocate 一样计入会话指标，
    /// 否则服务端会话 remove 时 fetch_sub(1) 会下溢成负数。
    pub fn register_specific(&self, session_id: u16) -> Option<mpsc::UnboundedReceiver<SessionEvent>> {
        if session_id == 0 {
            return None; // 0 保留给控制通道
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let mut map = self.sessions.lock().unwrap();
        if map.contains_key(&session_id) {
            return None; // 已占用
        }
        map.insert(session_id, tx);
        let m = crate::metrics::metrics();
        m.active_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        m.total_sessions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(rx)
    }

    /// 路由数据到指定会话（隧道接收循环调用）
    /// 返回是否路由成功（会话存在）
    pub fn route(&self, session_id: u16, event: SessionEvent) -> bool {
        let map = self.sessions.lock().unwrap();
        match map.get(&session_id) {
            Some(tx) => tx.send(event).is_ok(),
            None => false,
        }
    }

    /// 关闭全部会话通道（隧道断开时调用）
    ///
    /// 2026-08-19 S3 配套修复：此前隧道断开时只退出接收循环，会话通道的 Sender
    /// 留在注册表里不被清空 -> 各转发任务 `recv_event()` 永远等不到数据也收不到
    /// None（通道未关）-> 任务永久挂起（客户端转发任务泄漏，会话 ID 也无法复用）。
    /// 断链时应清空注册表：所有会话通道 Sender drop -> 转发任务 recv 返回 None
    /// 自然退出，active_sessions 同步递减。
    /// 返回被关闭的会话数。
    pub fn close_all(&self) -> usize {
        let mut map = self.sessions.lock().unwrap();
        let n = map.len();
        // 清空 map = drop 全部 Sender -> 各会话任务 recv_event() 得到 None 退出
        map.clear();
        // 递减会话指标（与 remove 一致，防止 active_sessions 虚高）
        let m = crate::metrics::metrics();
        m.active_sessions.fetch_sub(n as u64, std::sync::atomic::Ordering::Relaxed);
        n
    }

    /// 移除会话（会话结束或关闭时调用）
    pub fn remove(&self, session_id: u16) {
        let removed = self.sessions.lock().unwrap().remove(&session_id).is_some();
        // 接入会话指标（F2）：移除时递减 active_sessions
        if removed {
            let m = crate::metrics::metrics();
            m.active_sessions.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// 隧道会话句柄（一次会话的封装，包含发送与接收）
///
/// 使用方法：
/// 1. `SessionRegistry::allocate()` 得到 (session_id, rx)
/// 2. 用 `TunnelSession::new(...)` 封装
/// 3. `session.send_data(data)` 发送数据到隧道
/// 4. `session.recv().await` 从隧道接收数据
pub struct TunnelSession {
    /// 会话 ID
    pub session_id: u16,
    /// 接收通道（隧道 → 本会话）
    rx: mpsc::UnboundedReceiver<SessionEvent>,
    /// SRT 连接（发送用）
    conn: Arc<SrtConnection>,
    /// 复用编码器
    mux_enc: Arc<MuxEncoder>,
    /// 注册表（用于移除会话）
    registry: SessionRegistry,
}

impl TunnelSession {
    /// 创建隧道会话（由 SessionRegistry::allocate 后调用）
    ///
    /// 2026-08-19：移除 TS 伪装层，不再需要 ts_enc 参数。
    pub fn new(
        session_id: u16,
        rx: mpsc::UnboundedReceiver<SessionEvent>,
        conn: Arc<SrtConnection>,
        mux_enc: Arc<MuxEncoder>,
        registry: SessionRegistry,
    ) -> Self {
        Self {
            session_id,
            rx,
            conn,
            mux_enc,
            registry,
        }
    }

    /// 发送数据帧到隧道
    /// 大数据自动分片为多个隧道帧
    /// 注：常规转发路径用更高效的 send_data_batch，此方法保留为小块数据发送 API
    ///（UDP 转发方向使用），2026-08-19 审查修复（F2）：计入发送字节指标
    #[allow(dead_code)]
    pub async fn send_data(&self, data: &[u8]) -> Result<(), String> {
        // 按 FRAME_DATA_MAX 分片，每片一个 Data 帧（直接作为 SRT 消息发送，无 TS 壳）
        for chunk in data.chunks(FRAME_DATA_MAX) {
            let frame = self.mux_enc.encode_frame(
                FrameType::Data,
                self.session_id,
                0,
                chunk,
            );
            // 用异步发送（同步 send 会阻塞 worker，导致并发数据流停滞）
            self.conn.send_async(frame).await.map_err(|e| format!("发送数据帧失败: {e}"))?;
        }
        // 接入发送字节指标（F2）
        let m = crate::metrics::metrics();
        m.tx_bytes.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// 批量发送数据帧到隧道（带宽优化，2026-08-19）
    ///
    /// 优化点（移除 TS 伪装层后）：
    /// - 直接编码隧道帧（帧头 15B + payload），无 TS 壳开销
    /// - 一次收集所有帧后**同步投递**到发送通道（crossbeam unbounded send 不阻塞，
    ///   无需逐帧 await；消除每帧一次 tokio 任务切换的开销）
    /// - 适合大块数据（如 TCP 32KB 读缓冲），减少高频小包调度开销
    pub async fn send_data_batch(&self, data: &[u8]) -> Result<(), String> {
        // 一次编码所有分片为隧道帧（无 TS 壳，直接作为 SRT 消息）
        let mut pkts: Vec<Vec<u8>> = Vec::with_capacity(data.len().div_ceil(FRAME_DATA_MAX));
        for chunk in data.chunks(FRAME_DATA_MAX) {
            let frame = self.mux_enc.encode_frame(FrameType::Data, self.session_id, 0, chunk);
            pkts.push(frame);
        }

        // 同步投递所有帧：crossbeam unbounded channel 的 send 不阻塞，
        // 一次函数调用内投递全部，避免逐帧 await 让出 tokio 造成的调度开销
        for pkt in pkts {
            self.conn.send(pkt).map_err(|e| format!("发送数据帧失败: {e}"))?;
        }
        // 接入发送字节指标（F2）
        let m = crate::metrics::metrics();
        m.tx_bytes.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// 发送控制帧（Open/Close/Fin 等）
    pub async fn send_control(&self, ftype: FrameType, payload: &[u8]) -> Result<(), String> {
        let frame = self.mux_enc.encode_frame(ftype, self.session_id, 0, payload);
        // 用异步发送（无 TS 壳）
        self.conn.send_async(frame).await.map_err(|e| format!("发送控制帧失败: {e}"))
    }

    /// 从隧道接收事件（数据/半关闭/关闭）
    /// 返回 None 表示通道已关闭（连接断开或会话被移除）
    /// 2026-08-19 审查修复（B2）：返回事件而非原始数据，调用方可区分
    /// Data/Fin/Close，实现正确的半关闭语义
    ///
    /// 2026-08-19 审查修复（H5 rx_bytes 统一计数）：TCP 转发全走 recv_event，
    /// 旧实现只在 recv() 计数导致 rx_bytes 只反映 UDP 流量。
    /// 现统一在 recv_event 的 Data 分支计数（recv() 内部复用 recv_event 语义，不重复计）
    pub async fn recv_event(&mut self) -> Option<SessionEvent> {
        let ev = self.rx.recv().await?;
        if let SessionEvent::Data(d) = &ev {
            let m = crate::metrics::metrics();
            m.rx_bytes.fetch_add(d.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        Some(ev)
    }

    /// 从隧道接收数据（等数据 / 对端关闭时返回 None）
    /// 兼容旧调用场景：过滤出 Data 事件，FIN/Close 视为数据流结束
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            // 复用 recv_event（含 H5 统一计数），避免双处计数
            match self.recv_event().await? {
                SessionEvent::Data(d) => return Some(d),
                // FIN/Close 视为数据流结束
                SessionEvent::Fin | SessionEvent::Close => return None,
            }
        }
    }

    /// 发送 Open 帧（携带目标地址，通知对端建立转发连接）
    /// payload 格式：proto(1B) + host_len(1B) + host + port(2B BE)
    pub async fn send_open(&self, proto: u8, host: &str, port: u16) -> Result<(), String> {
        let mut payload = Vec::with_capacity(2 + host.len() + 2);
        payload.push(proto);
        payload.push(host.len() as u8);
        payload.extend_from_slice(host.as_bytes());
        payload.extend_from_slice(&port.to_be_bytes());
        self.send_control(FrameType::Open, &payload).await
    }

    /// 关闭会话（发送 Close 帧 + 从注册表移除）
    /// （P1 后半段接入会话管理时启用）
    #[allow(dead_code)]
    pub async fn close(&mut self) {
        let _ = self.send_control(FrameType::Close, &[]).await;
        self.registry.remove(self.session_id);
    }

    /// 发送半关闭 FIN（本端不再发数据，仍可收）
    pub async fn send_fin(&self) -> Result<(), String> {
        self.send_control(FrameType::Fin, &[]).await
    }
}

impl Drop for TunnelSession {
    fn drop(&mut self) {
        // 从注册表移除（会话结束）
        self.registry.remove(self.session_id);
    }
}

/// 隧道帧分发辅助：把收到的复用层帧按类型处理
///
/// 2026-08-19 审查修复（B2 半关闭语义）：
/// - Fin/Close 不再直接 registry.remove(sid)，而是作为事件投递到会话通道，
///   由会话任务决定何时真正结束（半关闭时剩余数据仍可路由，避免尾部数据丢失）
/// - 会话任务结束（Drop/显式 close）时自行移除注册表
pub fn dispatch_frame(
    frame: &Frame,
    registry: &SessionRegistry,
) -> DispatchAction {
    match frame.ftype {
        FrameType::Data => {
            // 数据帧：路由到对应会话
            if registry.route(frame.session_id, SessionEvent::Data(frame.payload.clone())) {
                DispatchAction::Routed
            } else {
                DispatchAction::UnknownSession(frame.session_id)
            }
        }
        FrameType::Fin => {
            // 半关闭信号：投递 Fin 事件（会话任务收到后停止接收、仍可发送）
            registry.route(frame.session_id, SessionEvent::Fin);
            DispatchAction::Fin(frame.session_id)
        }
        FrameType::Close => {
            // 对端完全关闭：投递 Close 事件（会话任务清理退出）
            registry.route(frame.session_id, SessionEvent::Close);
            DispatchAction::Closed(frame.session_id)
        }
        FrameType::Open => DispatchAction::Open(frame.session_id, frame.payload.clone()),
        _ => DispatchAction::Other,
    }
}

/// 帧分发动作结果（供接收循环匹配处理）
#[derive(Debug)]
pub enum DispatchAction {
    /// 数据已路由到会话
    Routed,
    /// 数据无法路由（会话不存在）
    UnknownSession(u16),
    /// 收到半关闭 FIN
    Fin(u16),
    /// 收到关闭
    Closed(u16),
    /// 收到打开请求（服务端处理）
    Open(u16, Vec<u8>),
    /// 其他帧（心跳/ACK 等，接收循环自行处理）
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    /// 从 UnboundedReceiver 非阻塞取一条事件（测试用）
    fn try_recv_event(rx: &mut mpsc::UnboundedReceiver<SessionEvent>) -> Option<SessionEvent> {
        rx.try_recv().ok()
    }

    /// 构造一个 Frame（供分发测试）
    fn mk_frame(ftype: FrameType, session_id: u16, payload: &[u8]) -> Frame {
        Frame {
            ftype,
            session_id,
            seq: 0,
            flags: 0,
            payload: payload.to_vec(),
        }
    }

    #[test]
    /// Data 帧路由到会话（事件型）
    fn test_dispatch_data_routes_event() {
        let reg = SessionRegistry::new();
        let (sid, mut rx) = reg.allocate().expect("分配成功");
        let frame = mk_frame(FrameType::Data, sid, b"hello");
        let act = dispatch_frame(&frame, &reg);
        assert!(matches!(act, DispatchAction::Routed), "应路由到已注册会话 {sid}");
        // 会话通道应收到 Data 事件
        let ev = try_recv_event(&mut rx).expect("应有事件");
        assert!(matches!(ev, SessionEvent::Data(d) if d == b"hello"));
    }

    #[test]
    /// Fin 帧不再删除会话，而是投递 Fin 事件（B2 半关闭语义）
    fn test_dispatch_fin_does_not_remove() {
        let reg = SessionRegistry::new();
        let (sid, mut rx) = reg.allocate().expect("分配成功");
        let frame = mk_frame(FrameType::Fin, sid, &[]);
        let act = dispatch_frame(&frame, &reg);
        assert!(matches!(act, DispatchAction::Fin(s) if s == sid));
        // 会话应仍存在（未被 dispatch 直接删除）
        assert!(reg.route(sid, SessionEvent::Data(b"x".to_vec())), "Fin 后会话仍可路由数据");
        // 会话通道收到 Fin 事件
        let ev = try_recv_event(&mut rx).expect("应有 Fin 事件");
        assert!(matches!(ev, SessionEvent::Fin));
    }

    #[test]
    /// Close 帧投递 Close 事件（会话由任务清理）
    fn test_dispatch_close_routes_event() {
        let reg = SessionRegistry::new();
        let (sid, mut rx) = reg.allocate().expect("分配成功");
        let frame = mk_frame(FrameType::Close, sid, &[]);
        let act = dispatch_frame(&frame, &reg);
        assert!(matches!(act, DispatchAction::Closed(s) if s == sid));
        let ev = try_recv_event(&mut rx).expect("应有 Close 事件");
        assert!(matches!(ev, SessionEvent::Close));
    }

    #[test]
    /// 会话上限：分配满 MAX_SESSIONS-1 后返回 None（F4）
    fn test_allocate_session_limit() {
        let reg = SessionRegistry::new();
        let mut allocated = 0;
        // 最多分配到 MAX_SESSIONS-1（0 保留控制通道）
        while let Some(_) = reg.allocate() {
            allocated += 1;
            assert!(allocated <= MAX_SESSIONS - 1);
        }
        assert_eq!(allocated, MAX_SESSIONS - 1, "应分配满上限");
    }

    #[test]
    /// ID 分配边界：大量分配后 ID 仍在 1..=255 且不重复复用已占用（F5）
    fn test_allocate_id_bounds() {
        let reg = SessionRegistry::new();
        let mut ids: Vec<u16> = Vec::new();
        // 最多分配的会话
        while let Some((sid, _rx)) = reg.allocate() {
            assert!(sid >= 1 && sid <= 255, "会话 ID 越界: {sid}");
            assert!(!ids.contains(&sid), "会话 ID 重复: {sid}");
            ids.push(sid);
        }
        // 移除一半再分配，应复用空闲 ID 且仍不越界
        for (i, sid) in ids.iter().enumerate().take(ids.len() / 2) {
            reg.remove(*sid);
            let _ = i;
        }
        while let Some((sid, _rx)) = reg.allocate() {
            assert!(sid >= 1 && sid <= 255);
        }
    }

    #[test]
    /// register_specific 拒绝 0（控制通道）与重复 ID
    fn test_register_specific_rejects_invalid() {
        let reg = SessionRegistry::new();
        assert!(reg.register_specific(0).is_none(), "0 保留控制通道");
        let rx = reg.register_specific(7).expect("合法 ID 注册成功");
        assert!(reg.register_specific(7).is_none(), "重复 ID 拒绝");
        let _ = rx;
        let frame = mk_frame(FrameType::Data, 7, b"z");
        let act = dispatch_frame(&frame, &reg);
        assert!(matches!(act, DispatchAction::Routed));
    }

    #[test]
    /// remove 后会话不存在，数据路由失败 + 指标递减由 registry 内部处理
    fn test_remove_after_close() {
        let reg = SessionRegistry::new();
        let (sid, _rx) = reg.allocate().expect("分配成功");
        reg.remove(sid);
        assert!(!reg.route(sid, SessionEvent::Data(b"x".to_vec())), "移除后路由失败");
    }
}
