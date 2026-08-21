//! 服务端模块
//!
//! 设计原因：服务端负责：
//! 1. 监听 UDP 端口（通过 TransportDriver）
//! 2. 接受 QUIC 连接
//! 3. 接收并验证 TUIC Authenticate 命令（UUID+password→TLS exporter token）
//! 4. 处理 Connect 命令（TCP 转发：建立到目标的 TCP 连接，双向桥接）
//! 5. 处理 Packet 命令（UDP 转发：建立到目标的 UDP socket，双向转发）
//! 6. 多客户端并发

pub mod auth;
pub mod forward;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::Config;
use crate::metrics::Metrics;
use crate::transport::driver::{DriverEvent, DriverRequest, TransportDriver};

/// 服务端运行入口
pub async fn run(config: Config, metrics: Arc<Metrics>) {
    let listen_addr = match config.listen_addr() {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!(error = %e, "服务端监听地址配置错误");
            return;
        }
    };

    // 加载 TLS 证书
    let cert_path = config.cert.as_ref().expect("服务端必须有 cert");
    let key_path = config.key.as_ref().expect("服务端必须有 key");
    let cert_pem = match std::fs::read(cert_path) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(path = cert_path, error = %e, "TLS 证书读取失败");
            return;
        }
    };
    let key_pem = match std::fs::read(key_path) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(path = key_path, error = %e, "TLS 私钥读取失败");
            return;
        }
    };

    let passphrase = config.passphrase.clone();
    let users = config.user_map(); // UUID → password
    let max_clients = config.max_clients;

    tracing::info!(addr = %listen_addr, users = users.len(), max_clients, "服务端启动");

    // 1. 绑定 UDP socket
    let socket = match UdpSocket::bind(listen_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "UDP 绑定失败");
            return;
        }
    };

    // 调大 UDP 缓冲区
    enlarge_socket_buffers(&socket);

    // 2. 创建传输驱动器
    let (req_tx, req_rx) = mpsc::unbounded_channel();
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();

    let driver = match TransportDriver::new_server(
        Arc::new(socket),
        &cert_pem,
        &key_pem,
        &passphrase,
        req_rx,
        event_tx,
    ) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "驱动器创建失败");
            return;
        }
    };

    // 3. 启动驱动器
    let mut driver_handle = tokio::spawn(async move {
        driver.run().await;
    });

    // 4. 服务端主循环：处理驱动器事件
    // 服务端模式：被动等待客户端连接，处理 Connect/Packet 命令
    let mut session_mgr = SessionManager::new(req_tx.clone(), users, max_clients, metrics.clone());

    loop {
        tokio::select! {
            event = event_rx.recv() => {
                match event {
                    Some(e) => {
                        if let Err(e) = session_mgr.handle_event(e).await {
                            tracing::error!(error = %e, "处理事件失败");
                        }
                    }
                    None => {
                        tracing::info!("驱动器事件通道关闭，服务端退出");
                        break;
                    }
                }
            }
            _ = &mut driver_handle => {
                tracing::warn!("传输驱动器退出");
                break;
            }
        }
    }

    tracing::info!("服务端退出");
}

/// 会话管理器
///
/// 管理客户端连接、认证状态、TCP/UDP 转发会话。
struct SessionManager {
    /// 驱动器请求通道
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    /// 用户表：UUID → password（用于 TUIC 认证验证）
    users: HashMap<Uuid, String>,
    /// 最大客户端连接数
    max_clients: usize,
    /// 指标
    metrics: Arc<Metrics>,
    /// 已认证的客户端连接数
    authenticated_count: usize,
    /// 活跃 TCP 转发会话（stream_id → 转发任务信息）
    /// 一旦流被记入此表，后续 StreamReadable 事件由转发任务自行处理
    tcp_sessions: HashMap<quinn_proto::StreamId, TcpSession>,
    /// 已处理的 uni-stream（避免重复读取 Auth 命令）
    handled_uni_streams: std::collections::HashSet<quinn_proto::StreamId>,
}

/// TCP 转发会话信息
struct TcpSession {
    /// 目标地址
    target_addr: Address,
}

impl SessionManager {
    fn new(
        req_tx: mpsc::UnboundedSender<DriverRequest>,
        users: HashMap<Uuid, String>,
        max_clients: usize,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            req_tx,
            users,
            max_clients,
            metrics,
            authenticated_count: 0,
            tcp_sessions: HashMap::new(),
            handled_uni_streams: std::collections::HashSet::new(),
        }
    }

    /// 处理驱动器事件
    async fn handle_event(&mut self, event: DriverEvent) -> Result<(), String> {
        match event {
            DriverEvent::Connected => {
                tracing::info!("客户端 QUIC 连接已建立");
            }
            DriverEvent::StreamReadable { stream_id } => {
                // 流有数据可读（driver 已读入缓冲）：解析 TUIC 命令或分发给转发任务
                self.handle_stream_readable(stream_id).await?;
            }
            DriverEvent::StreamFinished { stream_id } => {
                tracing::debug!(?stream_id, "流结束");
                // 只有真正的 TCP 会话流才减计数（防止 uni-stream 的下溢）
                if self.tcp_sessions.remove(&stream_id).is_some() {
                    self.metrics.dec_sessions();
                }
            }
            DriverEvent::StreamStopped { stream_id, error_code } => {
                tracing::debug!(?stream_id, error_code, "流被停止");
                if self.tcp_sessions.remove(&stream_id).is_some() {
                    self.metrics.dec_sessions();
                }
            }
            DriverEvent::ConnectionLost { reason } => {
                tracing::warn!(%reason, "客户端连接丢失");
                self.tcp_sessions.clear();
                self.authenticated_count = 0;
            }
            _ => {}
        }
        Ok(())
    }

    /// 处理流可读事件
    ///
    /// 收到 Readable 事件后，用 StreamRead 请求读取数据并解析 TUIC 命令。
    async fn handle_stream_readable(
        &mut self,
        stream_id: quinn_proto::StreamId,
    ) -> Result<(), String> {
        tracing::debug!(?stream_id, "服务端收到流可读事件");

        // 如果该流已有会话或已处理过，跳过（由转发任务接管）
        if self.tcp_sessions.contains_key(&stream_id) {
            return Ok(());
        }
        if self.handled_uni_streams.contains(&stream_id) {
            return Ok(());
        }

        // 从 QUIC 流读取数据（v2：无数据时在 driver 内挂起等待，有数据立即返回）
        let data = match request_stream_read(&self.req_tx, stream_id).await {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!(?stream_id, error = %e, "读取流失败");
                return Ok(());
            }
        };

        match data {
            Some(data) if !data.is_empty() => {
                // 尝试解析为 TUIC 命令
                match Command::decode(&data) {
                    Ok((cmd, consumed)) => {
                        let leftover = if consumed < data.len() {
                            Some(data[consumed..].to_vec())
                        } else {
                            None
                        };
                        self.handle_command(stream_id, cmd, leftover).await?;
                    }
                    Err(_) => {
                        tracing::debug!(?stream_id, len = data.len(), "流数据非 TUIC 命令，标记已处理");
                        self.handled_uni_streams.insert(stream_id);
                    }
                }
            }
            _ => {
                self.handled_uni_streams.insert(stream_id);
            }
        }
        Ok(())
    }

    /// 处理 TUIC 命令
    ///
    /// # 参数
    /// - `stream_id`: QUIC 流 ID
    /// - `cmd`: 解析出的 TUIC 命令
    /// - `leftover`: 读取流时命令之后剩余的数据（Connect 命令后紧跟的 HTTP 请求等）
    async fn handle_command(
        &mut self,
        stream_id: quinn_proto::StreamId,
        cmd: Command,
        leftover: Option<Vec<u8>>,
    ) -> Result<(), String> {
        match cmd {
            Command::Auth { uuid, token } => {
                // 认证命令：验证 token
                tracing::info!(?stream_id, ?uuid, "收到 Auth 命令，开始验证");
                let result = auth::verify_token(&uuid, &token, &self.users, &self.req_tx).await;
                match result {
                    Ok(true) => {
                        self.authenticated_count += 1;
                        tracing::info!(?uuid, "客户端认证成功");
                    }
                    Ok(false) => {
                        tracing::warn!(?uuid, "客户端认证失败（token 不匹配）");
                        // 关闭连接
                        let _ = request_close(&self.req_tx).await;
                    }
                    Err(e) => {
                        tracing::error!(?uuid, error = %e, "认证过程出错");
                        let _ = request_close(&self.req_tx).await;
                    }
                }
            }
            Command::Connect { addr } => {
                // TCP 连接命令：建立到目标的 TCP 连接
                tracing::info!(?stream_id, ?addr, "TCP Connect 命令");
                if self.authenticated_count == 0 {
                    tracing::warn!("未认证的 Connect 命令，拒绝");
                    let _ = request_stream_reset(&self.req_tx, stream_id, 1).await;
                    return Ok(());
                }
                if self.metrics.active_sessions.load(std::sync::atomic::Ordering::Relaxed) as usize
                    >= self.max_clients
                {
                    tracing::warn!("超过最大客户端数，拒绝连接");
                    let _ = request_stream_reset(&self.req_tx, stream_id, 1).await;
                    return Ok(());
                }

                // 记录会话
                self.tcp_sessions.insert(
                    stream_id,
                    TcpSession {
                        target_addr: addr.clone(),
                    },
                );
                self.metrics.inc_sessions();

                // 启动 TCP 转发任务（传入 leftover：Connect 命令后可能紧跟的数据）
                let req_tx = self.req_tx.clone();
                let metrics = self.metrics.clone();
                let sid = stream_id;
                tokio::spawn(async move {
                    if let Err(e) =
                        forward::handle_tcp_forward(sid, addr, req_tx, metrics, leftover).await
                    {
                        tracing::debug!(?sid, error = %e, "TCP 转发结束");
                    }
                });
            }
            Command::Packet { .. } => {
                // UDP 数据包命令（可靠模式，通过 bi-stream）
                // TODO: 完整 UDP 转发实现
                tracing::debug!(?stream_id, "UDP Packet 命令（待实现）");
            }
            Command::Dissociate { assoc_id } => {
                // 断开 UDP 关联
                tracing::debug!(assoc_id, "UDP Dissociate 命令");
            }
            Command::Heartbeat => {
                // 心跳命令，无需处理
                tracing::debug!("收到心跳");
            }
        }
        Ok(())
    }
}

/// 调大 UDP socket 缓冲区
fn enlarge_socket_buffers(socket: &UdpSocket) {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    let buf_size: libc::c_int = 4 * 1024 * 1024; // 4MB

    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&buf_size) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&buf_size) as libc::socklen_t,
        );
    }
}

// === 驱动器请求封装（服务端版） ===

use crate::tuic::addr::Address;
use crate::tuic::proto::Command;

/// 请求读取流数据（无数据时在 driver 内挂起等待，有数据立即返回）
async fn request_stream_read(
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
    stream_id: quinn_proto::StreamId,
) -> Result<Option<Vec<u8>>, String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    req_tx
        .send(DriverRequest::StreamRead {
            stream_id,
            reply: reply_tx,
        })
        .map_err(|_| "驱动器通道关闭".to_string())?;

    reply_rx
        .await
        .map_err(|_| "驱动器回复通道关闭".to_string())?
        .map_err(|e| format!("读取流失败: {}", e))
}

/// 请求重置流
async fn request_stream_reset(
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
    stream_id: quinn_proto::StreamId,
    error_code: u64,
) -> Result<(), String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    req_tx
        .send(DriverRequest::StreamReset {
            stream_id,
            error_code,
            reply: reply_tx,
        })
        .map_err(|_| "驱动器通道关闭".to_string())?;

    reply_rx
        .await
        .map_err(|_| "驱动器回复通道关闭".to_string())?
        .map_err(|e| format!("重置流失败: {}", e))
}

/// 请求关闭连接
async fn request_close(
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
) -> Result<(), String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    req_tx
        .send(DriverRequest::Close {
            reply: reply_tx,
        })
        .map_err(|_| "驱动器通道关闭".to_string())?;

    let _ = reply_rx.await;
    Ok(())
}
