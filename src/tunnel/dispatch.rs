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
use crate::tunnel::FrameType;

// FRAME_DATA_MAX 复用 multiplex.rs 的定义（SRT 原生大包 1301B，2026-08-19 移除 TS 伪装）。
// 注意：不要在本文件重复定义旧值（曾错误地保留 169，导致分片仍是 169B 小包、
// 全双工吞吐塌陷）。

/// 会话注册表（隧道接收循环与各会话处理任务共享）
#[derive(Clone)]
pub struct SessionRegistry {
    /// 会话 ID → 接收通道发送端（会话处理任务消费）
    sessions: Arc<std::sync::Mutex<HashMap<u16, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// 下一个会话 ID（递增分配）
    next_id: Arc<std::sync::atomic::AtomicU16>,
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
            next_id: Arc::new(std::sync::atomic::AtomicU16::new(1)),
        }
    }

    /// 分配新会话，返回 (会话 ID, 接收通道接收端)
    /// 接收端用于会话处理任务读取来自隧道的数据
    pub fn allocate(&self) -> (u16, mpsc::UnboundedReceiver<Vec<u8>>) {
        // 循环找空闲 ID（0 保留给控制通道，1..=255 会话）
        let (tx, rx) = mpsc::unbounded_channel();
        let id = loop {
            let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let id = if id == 0 { 1 } else { id & 0xFF }; // 限制在 1..=255
            let mut map = self.sessions.lock().unwrap();
            if !map.contains_key(&id) {
                map.insert(id, tx);
                break id;
            }
        };
        (id, rx)
    }

    /// 按指定会话 ID 注册接收通道（服务端转发用）
    ///
    /// 服务端在收到客户端 Open 帧时，会话 ID 已由客户端决定，
    /// 转发任务需要按该 ID 注册自己的接收通道。
    /// 返回 None 表示 ID 已被占用（0 保留或重复）。
    pub fn register_specific(&self, session_id: u16) -> Option<mpsc::UnboundedReceiver<Vec<u8>>> {
        if session_id == 0 {
            return None; // 0 保留给控制通道
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let mut map = self.sessions.lock().unwrap();
        if map.contains_key(&session_id) {
            return None; // 已占用
        }
        map.insert(session_id, tx);
        Some(rx)
    }

    /// 路由数据到指定会话（隧道接收循环调用）
    /// 返回是否路由成功（会话存在）
    pub fn route(&self, session_id: u16, data: Vec<u8>) -> bool {
        let map = self.sessions.lock().unwrap();
        match map.get(&session_id) {
            Some(tx) => tx.send(data).is_ok(),
            None => false,
        }
    }

    /// 移除会话（会话结束或关闭时调用）
    pub fn remove(&self, session_id: u16) {
        self.sessions.lock().unwrap().remove(&session_id);
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
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
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
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
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
        Ok(())
    }

    /// 发送控制帧（Open/Close/Fin 等）
    pub async fn send_control(&self, ftype: FrameType, payload: &[u8]) -> Result<(), String> {
        let frame = self.mux_enc.encode_frame(ftype, self.session_id, 0, payload);
        // 用异步发送（无 TS 壳）
        self.conn.send_async(frame).await.map_err(|e| format!("发送控制帧失败: {e}"))
    }

    /// 从隧道接收数据（会话处理任务调用）
    /// 返回 None 表示会话已关闭/连接断开
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
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
/// 返回 Data 帧是否已路由（供调用方决定是否额外处理）
pub fn dispatch_frame(
    frame: &Frame,
    registry: &SessionRegistry,
) -> DispatchAction {
    match frame.ftype {
        FrameType::Data => {
            // 数据帧：路由到对应会话
            if registry.route(frame.session_id, frame.payload.clone()) {
                DispatchAction::Routed
            } else {
                DispatchAction::UnknownSession(frame.session_id)
            }
        }
        FrameType::Fin => DispatchAction::Fin(frame.session_id),
        FrameType::Close => {
            // 对端关闭会话
            registry.remove(frame.session_id);
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
