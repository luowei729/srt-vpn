//! metrics.rs — 运行指标（回环 HTTP 端口）
//!
//! 设计决策（Q22）：回环 HTTP 指标端口（仅监听 127.0.0.1）
//! - 暴露连接数、吞吐、丢包率、会话数等运行状态
//! - P1 实现简单计数器，P2 扩展实时统计

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::AsyncWriteExt;

/// 全局指标（进程级单例）
#[derive(Debug, Default)]
pub struct Metrics {
    /// 当前活跃 SRT 连接数
    pub active_connections: AtomicU64,
    /// 累计连接次数
    pub total_connections: AtomicU64,
    /// 当前活跃会话数（隧道复用层）
    pub active_sessions: AtomicU64,
    /// 累计会话次数
    pub total_sessions: AtomicU64,
    /// 发送字节数（隧道载荷）
    pub tx_bytes: AtomicU64,
    /// 接收字节数（隧道载荷）
    pub rx_bytes: AtomicU64,
    /// 认证失败次数
    pub auth_failures: AtomicU64,
    /// 心跳超时次数
    pub heartbeat_timeouts: AtomicU64,
    /// 最近一次心跳 RTT（毫秒，M8 2026-08-19 新增：pong 时间戳差值）
    pub last_rtt_ms: AtomicU64,
}

/// 全局指标实例（OnceLock 懒初始化）
static METRICS: std::sync::OnceLock<Arc<Metrics>> = std::sync::OnceLock::new();

/// 获取全局指标
pub fn metrics() -> Arc<Metrics> {
    METRICS
        .get_or_init(|| Arc::new(Metrics::default()))
        .clone()
}

impl Metrics {
    /// 启动回环 HTTP 指标服务（阻塞式，由调用方 spawn）
    /// 仅监听 127.0.0.1，不对外暴露
    pub async fn serve_http(port: u16) -> Result<(), String> {
        let addr = format!("127.0.0.1:{port}");
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("指标端口绑定失败 {addr}: {e}"))?;
        tracing::info!(addr = %addr, "指标 HTTP 服务已启动");
        loop {
            let (mut sock, _) = listener
                .accept()
                .await
                .map_err(|e| format!("指标 HTTP accept 失败: {e}"))?;
            // 每个连接独立任务，响应 JSON 指标
            tokio::spawn(async move {
                let body = render_metrics_json();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    }
}

/// 渲染指标为 JSON 字符串（text/plain 简单格式）
fn render_metrics_json() -> String {
    let m = metrics();
    serde_json::json!({
        "active_connections": m.active_connections.load(Ordering::Relaxed),
        "total_connections": m.total_connections.load(Ordering::Relaxed),
        "active_sessions": m.active_sessions.load(Ordering::Relaxed),
        "total_sessions": m.total_sessions.load(Ordering::Relaxed),
        "tx_bytes": m.tx_bytes.load(Ordering::Relaxed),
        "rx_bytes": m.rx_bytes.load(Ordering::Relaxed),
        "auth_failures": m.auth_failures.load(Ordering::Relaxed),
        "heartbeat_timeouts": m.heartbeat_timeouts.load(Ordering::Relaxed),
        "last_rtt_ms": m.last_rtt_ms.load(Ordering::Relaxed),
    })
    .to_string()
}
