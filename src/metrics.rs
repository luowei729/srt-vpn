//! 回环 HTTP 指标端口模块
//!
//! 设计原因：提供运行时可观测性（活跃会话数、收发字节数等）。
//! 指标通过 HTTP 暴露在回环地址，不占外部端口，不影响 passwall 配置。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 全局运行时指标（原子计数器，无锁高性能）
#[derive(Debug, Default)]
pub struct Metrics {
    /// 活跃会话数（TCP+UDP）
    pub active_sessions: AtomicU64,
    /// 累计接收字节数（从隧道收到的）
    pub rx_bytes: AtomicU64,
    /// 累计发送字节数（发往隧道的）
    pub tx_bytes: AtomicU64,
    /// 累计连接数（客户端连接/重连次数）
    pub total_connections: AtomicU64,
}

impl Metrics {
    /// 创建新的指标实例
    pub fn new() -> Self {
        Self::default()
    }

    /// 增加活跃会话数
    pub fn inc_sessions(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// 减少活跃会话数
    pub fn dec_sessions(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    /// 增加接收字节数
    pub fn add_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// 增加发送字节数
    pub fn add_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// 增加连接计数
    pub fn inc_connections(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// 渲染为 JSON 字符串（HTTP 响应体）
    fn to_json(&self) -> String {
        format!(
            r#"{{"active_sessions":{},"rx_bytes":{},"tx_bytes":{},"total_connections":{}}}"#,
            self.active_sessions.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
            self.total_connections.load(Ordering::Relaxed),
        )
    }
}

/// 启动指标 HTTP 服务
///
/// # 参数
/// - `metrics`: 共享指标实例
/// - `port`: 监听端口（回环地址 127.0.0.1:port）
///
/// # 设计
/// 用最简 HTTP 响应（不引入 axum/actix 框架），直接裸 TCP 返回 JSON。
/// 只监听 127.0.0.1，不暴露到外部网络。
pub async fn serve(metrics: Arc<Metrics>, port: u16) {
    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, port, "指标端口监听失败");
            return;
        }
    };
    tracing::info!(port, "指标服务已启动");

    loop {
        // 接受连接，每连接返回一次指标 JSON
        let (mut sock, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "指标端口 accept 失败");
                continue;
            }
        };

        let metrics = metrics.clone();
        tokio::spawn(async move {
            // 读取 HTTP 请求行（忽略内容，只关心返回响应）
            let mut buf = [0u8; 256];
            let _ = sock.read(&mut buf).await;

            // 构造 HTTP 响应
            let body = metrics.to_json();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );

            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.flush().await;
            let _ = addr; // 仅记录，不使用
        });
    }
}
