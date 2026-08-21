//! TCP/UDP 转发模块（服务端）
//!
//! 设计原因：服务端收到 TUIC Connect 命令后，建立到目标的 TCP 连接，
//! 双向桥接：QUIC 流 ↔ 目标 TCP 连接。
//! UDP 转发类似，建立到目标的 UDP socket。

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::metrics::Metrics;
use crate::transport::driver::DriverRequest;
use crate::tuic::addr::Address;

/// 处理 TCP 转发（服务端）
///
/// 收到 Connect 命令后建立到目标的 TCP 连接，双向桥接：
/// - 上行：QUIC 流 → 目标 TCP（读取 QUIC 流数据写入 TCP）
/// - 下行：目标 TCP → QUIC 流（读取 TCP 数据写入 QUIC 流）
///
/// # 参数
/// - `leftover`: Connect 命令后可能紧跟的数据（如 HTTP 请求），需先写入 TCP
pub async fn handle_tcp_forward(
    stream_id: quinn_proto::StreamId,
    target_addr: Address,
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    metrics: Arc<Metrics>,
    leftover: Option<Vec<u8>>,
) -> Result<(), String> {
    // 1. 解析目标地址并建立 TCP 连接
    let target = match target_addr.to_socket_addr() {
        Some(addr) => addr,
        None => {
            // 域名需要 DNS 解析
            match resolve_address(&target_addr).await {
                Some(addr) => addr,
                None => {
                    tracing::warn!(?target_addr, "DNS 解析失败");
                    let _ = request_stream_reset(&req_tx, stream_id, 1).await;
                    return Err("DNS 解析失败".into());
                }
            }
        }
    };

    let mut tcp_stream = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(target),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tracing::warn!(?target, error = %e, "TCP 连接失败");
            let _ = request_stream_reset(&req_tx, stream_id, 1).await;
            return Err(format!("TCP 连接失败: {}", e));
        }
        Err(_) => {
            tracing::warn!(?target, "TCP 连接超时");
            let _ = request_stream_reset(&req_tx, stream_id, 1).await;
            return Err("TCP 连接超时".into());
        }
    };

    tracing::info!(?stream_id, ?target, "TCP 转发已建立");

    // 2. 用 TcpStream::into_split 拆分读写半
    let (tcp_read, mut tcp_write) = tcp_stream.into_split();

    // 3. 先写入 leftover 数据（Connect 命令后紧跟的数据，如 HTTP 请求头）
    if let Some(extra) = leftover {
        if !extra.is_empty() {
            tracing::debug!(?stream_id, len = extra.len(), "写入 Connect 后残留数据");
            if let Err(e) = tcp_write.write_all(&extra).await {
                tracing::debug!(?stream_id, error = %e, "写入残留数据失败");
                let _ = request_stream_reset(&req_tx, stream_id, 1).await;
                return Err(format!("写入残留数据失败: {}", e));
            }
            metrics.add_rx(extra.len() as u64);
        }
    }

    // 4. 准备双向桥接
    let req_tx_down = req_tx.clone();
    let req_tx_up = req_tx.clone();
    let metrics_down = metrics.clone();
    let metrics_up = metrics.clone();

    // 3. 双向桥接
    // 上行任务：QUIC 流 → 目标 TCP（从 QUIC 读数据写入 TCP）
    // 下行任务：目标 TCP → QUIC 流（从 TCP 读数据写入 QUIC 流）

    // 下行任务：目标 TCP → QUIC 流
    let down_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut tcp_read = tcp_read;
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    // TCP 连接关闭
                    let _ = request_stream_finish(&req_tx_down, stream_id).await;
                    break;
                }
                Ok(n) => {
                    let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                    match request_stream_write(&req_tx_down, stream_id, data).await {
                        Ok(written) => {
                            metrics_down.add_tx(written as u64);
                        }
                        Err(e) => {
                            tracing::debug!(?stream_id, error = %e, "QUIC 写入失败");
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(?stream_id, error = %e, "TCP 读取失败");
                    let _ = request_stream_reset(&req_tx_down, stream_id, 1).await;
                    break;
                }
            }
        }
    });

    // 上行任务：QUIC 流 → 目标 TCP
    // v2：StreamRead 无数据时在 driver 内挂起等待（pending reply），
    // 有数据立即返回，无轮询延迟
    let up_handle = tokio::spawn(async move {
        loop {
            match request_stream_read(&req_tx_up, stream_id).await {
                Ok(Some(data)) => {
                    metrics_up.add_rx(data.len() as u64);
                    // 写入目标 TCP
                    if let Err(e) = tcp_write.write_all(&data).await {
                        tracing::debug!(?stream_id, error = %e, "TCP 写入失败");
                        break;
                    }
                }
                Ok(None) => {
                    // QUIC 流结束（FIN）
                    tracing::debug!(?stream_id, "QUIC 流结束，关闭 TCP");
                    break;
                }
                Err(e) => {
                    tracing::debug!(?stream_id, error = %e, "QUIC 流读取失败");
                    break;
                }
            }
        }
    });

    // 等待任意任务结束
    tokio::select! {
        _ = up_handle => {}
        _ = down_handle => {}
    }

    metrics.dec_sessions();
    tracing::debug!(?stream_id, "TCP 转发结束");
    Ok(())
}

/// DNS 解析域名地址
async fn resolve_address(addr: &Address) -> Option<std::net::SocketAddr> {
    match addr {
        Address::Domain(host, port) => {
            // 域名 DNS 解析（用 (host, port) 元组形式，lookup_host 直接接受）
            match tokio::net::lookup_host((host.as_str(), *port)).await {
                Ok(mut addrs) => addrs.next(),
                Err(e) => {
                    tracing::warn!(host, error = %e, "DNS 解析失败");
                    None
                }
            }
        }
        Address::IPv4(ip, port) => Some(std::net::SocketAddr::new((*ip).into(), *port)),
        Address::IPv6(ip, port) => Some(std::net::SocketAddr::new((*ip).into(), *port)),
        Address::None => None,
    }
}

// === 驱动器请求封装 ===

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

/// 请求结束流发送方向（FIN）
async fn request_stream_finish(
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
    stream_id: quinn_proto::StreamId,
) -> Result<(), String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    req_tx
        .send(DriverRequest::StreamFinish {
            stream_id,
            reply: reply_tx,
        })
        .map_err(|_| "驱动器通道关闭".to_string())?;

    reply_rx
        .await
        .map_err(|_| "驱动器回复通道关闭".to_string())?
        .map_err(|e| format!("FIN 失败: {}", e))
}

/// 请求写入流数据
#[allow(dead_code)]
async fn request_stream_write(
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
    stream_id: quinn_proto::StreamId,
    data: bytes::Bytes,
) -> Result<usize, String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    req_tx
        .send(DriverRequest::StreamWrite {
            stream_id,
            data,
            reply: reply_tx,
        })
        .map_err(|_| "驱动器通道关闭".to_string())?;

    reply_rx
        .await
        .map_err(|_| "驱动器回复通道关闭".to_string())?
        .map_err(|e| format!("写入流失败: {}", e))
}
