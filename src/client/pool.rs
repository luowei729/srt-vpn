//! client/pool.rs — 多 SRT 连接池（B 方案，2026-08-20）
//!
//! 设计背景（公网对照实验结论，见 CHANGELOG 05:30）：
//! 纯 libsrt 探针实测：公网单 SRT 连接上传 89 MB/s，4 连接并发 151 MB/s（+70%）。
//! 根因：单 SRT 连接共享一个 FileCC 拥塞窗口（带宽×RTT 的物理上限），
//! 多会话并发时共享窗口被瓜分、总吞吐受限。A 方案（复用层公平调度）已验证
//! 无法突破单连接天花板（回环 4 并发 302→36 MB/s，每 32KB 一次 await 调度开销）。
//!
//! B 方案：客户端维护 N 条独立 SRT 连接，每条有独立的 FileCC 拥塞窗口，
//! 等价于 QUIC 的"每流独立窗口"（甚至更彻底）。会话按轮询分配到各连接，
//! 使并发会话分散到多条连接、各自全力发送，突破单连接带宽上限。
//!
//! 代价：多 UDP 流（伪装从"单流"变"多流"），但都连同一服务器端口，
//! NAT 层面仍是同一对端，可通过池大小平衡伪装与吞吐。

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::quic::connection::QuicConnection;
use crate::tunnel::dispatch::{SessionEvent, SessionRegistry};
use crate::tunnel::multiplex::MuxEncoder;

/// 单条隧道连接的三元组（连接 + 编码器 + 会话注册表）
///
/// 每条连接是一个独立的 SRT 隧道：独立的 FileCC 拥塞窗口、独立的
/// SessionRegistry（会话 ID 空间 1..=255 各自独立，跨连接无冲突）、
/// 独立的 MuxEncoder（帧序号独立）。
#[derive(Clone)]
pub struct TunnelConn {
    /// QUIC 连接（2026-08-20 重构：替代 SrtConnection）
    pub conn: Arc<QuicConnection>,
    /// 复用层编码器
    pub mux_enc: Arc<MuxEncoder>,
    /// 会话注册表（本连接内独立）
    pub registry: SessionRegistry,
}

/// 多 SRT 连接池
///
/// 会话分配采用**轮询（round-robin）**：每个新会话按原子计数器选下一条连接，
/// 保证并发会话均匀分散到 N 条连接，各自利用独立的拥塞窗口。
pub struct TunnelPool {
    /// 连接池（N 条，固定大小）
    conns: Vec<TunnelConn>,
    /// 轮询分配计数器（原子递增，跨 tokio task 安全）
    next: AtomicUsize,
}

impl TunnelPool {
    /// 由 N 条已建立的连接构建连接池
    pub fn new(conns: Vec<TunnelConn>) -> Self {
        assert!(!conns.is_empty(), "连接池不能为空");
        Self {
            conns,
            next: AtomicUsize::new(0),
        }
    }

    /// 池大小（连接数）
    pub fn len(&self) -> usize {
        self.conns.len()
    }

    /// 轮询分配一个会话，返回 (选中的连接, 会话 ID, 接收通道)
    ///
    /// 在选中连接的 registry 上 allocate（会话 ID 仅在该连接内有效）。
    /// 返回完整的 TunnelConn（含正确的 conn/mux_enc/registry，调用方据此
    /// 构造 TunnelSession，Drop 时能 remove 到正确连接的注册表）。
    /// 返回 None 表示选中连接的会话数已满（255 上限，极罕见）。
    pub fn allocate(
        &self,
    ) -> Option<(TunnelConn, u16, tokio::sync::mpsc::UnboundedReceiver<SessionEvent>)> {
        // 轮询：原子递增取模，均匀分散
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.conns.len();
        let c = &self.conns[idx];
        let (sid, rx) = c.registry.allocate()?;
        Some((c.clone(), sid, rx))
    }

    /// 按索引取连接（供 recv_loop 等按连接维度操作，如心跳）
    pub fn get(&self, idx: usize) -> &TunnelConn {
        &self.conns[idx]
    }

    /// 关闭全部连接（整体重连时调用；每条连接的会话通道由 close_all 清空）
    pub fn close_all_sessions(&self) -> usize {
        self.conns
            .iter()
            .map(|c| c.registry.close_all())
            .sum()
    }
}
