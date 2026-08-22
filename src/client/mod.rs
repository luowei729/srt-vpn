//! 客户端模块
//!
//! 设计原因：客户端负责：
//! 1. 建立 QUIC 连接到服务端（通过 TransportDriver）
//! 2. QUIC 握手完成后发送 TUIC Authenticate 命令（UUID+password→TLS exporter token）
//! 3. 本地监听 SOCKS5+HTTP 三合一代理端口（首字节嗅探分流）
//! 4. 将代理请求映射为 TUIC 命令（TCP→Connect/bi-stream, UDP→Packet/bi-stream）
//! 5. 断线自动重连

pub mod proxy;
pub mod socks5;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use uuid::Uuid;

use crate::config::Config;
use crate::metrics::Metrics;
use crate::transport::driver::{DriverEvent, DriverRequest, TransportDriver};

/// 客户端运行入口
///
/// 负责连接管理 + 重连循环。SOCKS5 代理入口由 socks5::serve 处理。
pub async fn run(config: Config, metrics: Arc<Metrics>) {
    let server_addr = config.server.as_ref().expect("客户端必须有 server");
    let server_addr: SocketAddr = match server_addr.parse() {
        Ok(addr) => addr,
        Err(_) => {
            // 域名：拆出 host 与 port，用 lookup_host 解析
            let (host, port_str) = server_addr.rsplit_once(':').unwrap_or((server_addr.as_str(), "9000"));
            let port: u16 = port_str.parse().unwrap_or(9000);
            // 去掉 IPv6 中括号（lookup_host 不需要）
            let host_clean = host.trim_matches(|c| c == '[' || c == ']');
            match tokio::net::lookup_host((host_clean, port)).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        addr
                    } else {
                        tracing::error!("DNS 解析无结果: {}", server_addr);
                        return;
                    }
                }
                Err(e) => {
                    tracing::error!(server = %server_addr, error = %e, "DNS 解析失败");
                    return;
                }
            }
        }
    };

    let uuid = config.uuid.expect("客户端必须有 uuid");
    let password = config.password.clone().expect("客户端必须有 password");
    let passphrase = config.passphrase.clone();
    let socks5_addr = config.socks5_listen_addr().expect("客户端必须有 socks5.listen");
    let heartbeat_secs = config.heartbeat_secs;
    let reconnect_interval = config.reconnect.interval_secs;
    let reconnect_max = config.reconnect.max_retries;

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        metrics.inc_connections();

        tracing::info!(attempt, server = %server_addr, "开始建立连接");

        match connect_and_serve(
            server_addr,
            &uuid,
            &password,
            &passphrase,
            socks5_addr,
            heartbeat_secs,
            metrics.clone(),
        )
        .await
        {
            Ok(()) => {
                tracing::info!("连接正常关闭");
                break; // 正常关闭，不重连
            }
            Err(e) => {
                tracing::warn!(attempt, error = %e, "连接断开");

                // 检查是否超过最大重连次数
                if reconnect_max > 0 && attempt >= reconnect_max {
                    tracing::error!(attempt, max = reconnect_max, "达到最大重连次数，退出");
                    break;
                }

                // 等待重连间隔
                tracing::info!(interval_secs = reconnect_interval, "等待重连...");
                tokio::time::sleep(Duration::from_secs(reconnect_interval)).await;
            }
        }
    }
}

/// 建立连接并运行代理服务
///
/// 返回 Ok(()) 表示正常关闭，Err 表示需要重连。
async fn connect_and_serve(
    server_addr: SocketAddr,
    uuid: &Uuid,
    password: &str,
    passphrase: &str,
    socks5_addr: SocketAddr,
    heartbeat_secs: u64,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    // 1. 绑定本地 UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("UDP 绑定失败: {}", e))?;

    // 调大 UDP 接收缓冲区（高吞吐防溢出丢包）
    enlarge_socket_buffers(&socket);

    // 2. 创建传输驱动器
    let (req_tx, req_rx) = mpsc::unbounded_channel();
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();

    let driver = TransportDriver::new_client(
        Arc::new(socket),
        server_addr,
        "srt-vpn", // SNI（跳过证书验证，不实际使用）
        passphrase,
        req_rx,
        event_tx,
    )
    .map_err(|e| format!("驱动器创建失败: {}", e))?;

    // 3. 启动驱动器（独立 tokio 任务）
    let driver_handle = tokio::spawn(async move {
        driver.run().await;
    });

    // 4. 等待 QUIC 连接建立（等待 Connected 事件）
    let connected = wait_for_event(&mut event_rx, |e| matches!(e, DriverEvent::Connected))
        .await;

    if !connected {
        let _ = driver_handle.abort();
        return Err("QUIC 连接建立超时".into());
    }

    tracing::info!("QUIC 连接已建立");

    // 5. 发送 TUIC Authenticate 命令
    // token = TLS exporter(label=uuid, context=password, output=32B)
    let uuid_bytes = uuid.as_bytes().to_vec();
    let token = request_export_keying_material(
        &req_tx,
        32,
        uuid_bytes.clone(),
        password.as_bytes().to_vec(),
    )
    .await
    .map_err(|e| format!("TLS exporter 失败: {}", e))?;

    // 构建 Authenticate 命令并发送（通过 uni-stream）
    let mut token_arr = [0u8; 32];
    token_arr.copy_from_slice(&token);
    let auth_cmd = crate::tuic::proto::Command::Auth {
        uuid: *uuid,
        token: token_arr,
    };
    let auth_data = bytes::Bytes::from(auth_cmd.encode_to_vec());

    tracing::info!("发送 TUIC Authenticate 命令");
    request_send_uni_stream(&req_tx, auth_data)
        .await
        .map_err(|e| format!("发送认证命令失败: {}", e))?;

    tracing::info!("TUIC 认证完成");

    // 等待 Auth 命令被服务端处理（200ms 确保先于 Connect 命令到达）
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6. 启动心跳定时器
    let heartbeat_tx = req_tx.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(heartbeat_secs.max(1)));
        // TUIC 原版心跳命令通过 uni-stream 发送
        let heartbeat_cmd = crate::tuic::proto::Command::Heartbeat;
        let heartbeat_data = bytes::Bytes::from(heartbeat_cmd.encode_to_vec());
        loop {
            interval.tick().await;
            // 发送心跳（通过 uni-stream）
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if heartbeat_tx
                .send(DriverRequest::SendUniStream {
                    data: heartbeat_data.clone(),
                    reply: reply_tx,
                })
                .is_err()
            {
                break; // 驱动器已关闭
            }
            let _ = reply_rx.await; // 忽略心跳发送结果
        }
    });

    // 7. 启动 SOCKS5+HTTP 三合一代理入口
    let proxy_req_tx = req_tx.clone();
    let proxy_metrics = metrics.clone();
    let socks5_handle = tokio::spawn(async move {
        if let Err(e) = socks5::serve(socks5_addr, proxy_req_tx, event_rx, proxy_metrics).await {
            tracing::error!(error = %e, "SOCKS5 代理服务异常退出");
        }
    });

    // 8. 等待任意子任务结束
    // 任一子任务退出都意味着本条连接生命周期结束（驱动器死 / 代理退出）。
    let reason: String = tokio::select! {
        _ = driver_handle => {
            tracing::warn!("传输驱动器退出");
            "传输驱动器退出".to_string()
        }
        _ = socks5_handle => {
            tracing::warn!("SOCKS5 代理服务退出");
            "SOCKS5 代理服务退出".to_string()
        }
    };

    heartbeat_handle.abort();

    // 返回 Err 让 run() 重连循环接管；Ok(()) 仅用于进程正常退出路径
    Err(reason)
}

/// 等待特定事件（带 15 秒超时）
async fn wait_for_event<F>(
    event_rx: &mut mpsc::UnboundedReceiver<DriverEvent>,
    predicate: F,
) -> bool
where
    F: Fn(&DriverEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        tokio::select! {
            event = event_rx.recv() => {
                match event {
                    Some(e) if predicate(&e) => return true,
                    Some(e) => {
                        // 其他事件，继续等待
                        match e {
                            DriverEvent::ConnectionLost { reason } => {
                                tracing::warn!(%reason, "连接丢失");
                                return false;
                            }
                            _ => {} // 其他事件忽略
                        }
                    }
                    None => return false, // 通道关闭
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                tracing::warn!("等待事件超时");
                return false;
            }
        }
    }
}

/// 请求 TLS exporter 密钥材料
async fn request_export_keying_material(
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
    output_len: usize,
    label: Vec<u8>,
    context: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    req_tx
        .send(DriverRequest::ExportKeyingMaterial {
            output_len,
            label,
            context,
            reply: reply_tx,
        })
        .map_err(|_| "驱动器通道关闭".to_string())?;

    reply_rx
        .await
        .map_err(|_| "驱动器回复通道关闭".to_string())?
        .map_err(|e| format!("exporter 错误: {}", e))
}

/// 请求发送 uni-stream 数据
async fn request_send_uni_stream(
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
    data: bytes::Bytes,
) -> Result<(), String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    req_tx
        .send(DriverRequest::SendUniStream { data, reply: reply_tx })
        .map_err(|_| "驱动器通道关闭".to_string())?;

    reply_rx
        .await
        .map_err(|_| "驱动器回复通道关闭".to_string())?
        .map_err(|e| format!("发送 uni-stream 错误: {}", e))
}

/// 调大 UDP socket 缓冲区（高吞吐防接收缓冲溢出丢包）
///
/// 内核默认 rmem_max 可能只有 208KB，高吞吐时会溢出导致丢包。
fn enlarge_socket_buffers(socket: &UdpSocket) {
    use std::os::fd::AsRawFd;
    const SO_RCVBUF: libc::c_int = libc::SO_RCVBUF;
    const SO_SNDBUF: libc::c_int = libc::SO_SNDBUF;

    let fd = socket.as_raw_fd();
    let buf_size: libc::c_int = 4 * 1024 * 1024; // 4MB

    unsafe {
        // 设置接收缓冲区
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_RCVBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&buf_size) as libc::socklen_t,
        );
        if ret != 0 {
            tracing::warn!("设置 SO_RCVBUF 失败（内核 rmem_max 可能限制）");
        }

        // 设置发送缓冲区
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_SNDBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&buf_size) as libc::socklen_t,
        );
        if ret != 0 {
            tracing::warn!("设置 SO_SNDBUF 失败（内核 wmem_max 可能限制）");
        }
    }
}
