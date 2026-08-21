//! TCP/UDP 代理转发模块
//!
//! 设计原因：将 SOCKS5/HTTP 代理请求映射为 TUIC 命令：
//! - TCP 代理（SOCKS5 CONNECT / HTTP CONNECT）→ TUIC Connect 命令（QUIC bi-stream）
//! - UDP 代理（SOCKS5 UDP ASSOCIATE）→ TUIC Packet 命令（QUIC bi-stream，可靠模式）
//!
//! 每个 TCP 连接 = 一条 QUIC 双向流，天然多路复用。
//! UDP 也走双向流（可靠模式），与 TUIC 的 quic 模式一致。

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::metrics::Metrics;
use crate::transport::driver::DriverRequest;
use crate::tuic::addr::Address;
use crate::tuic::proto::Command;

/// 最大 TUIC 命令帧大小（Packet 命令含 payload）
const MAX_PACKET_PAYLOAD: usize = 1300;

/// 处理 TCP CONNECT 代理（SOCKS5 CONNECT / HTTP CONNECT 隧道）
///
/// 流程：
/// 1. 通过 QUIC bi-stream 发送 Connect 命令（含目标地址）
/// 2. 双向桥接本地 TCP 流 ↔ QUIC bi-stream
pub async fn handle_tcp_connect(
    local_stream: TcpStream,
    target_addr: Address,
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    handle_tcp_connect_inner(local_stream, target_addr, req_tx, metrics, None).await
}

/// 带首包数据的 TCP 代理转发（普通 HTTP 代理模式用）
///
/// 与 handle_tcp_connect 相同，但 prepend 数据（重构后的 HTTP 请求头）
/// 会在 Connect 命令后立即写入 QUIC 流，服务端通过 leftover 通道先写入目标。
pub async fn handle_tcp_connect_with_prepend(
    local_stream: TcpStream,
    target_addr: Address,
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    metrics: Arc<Metrics>,
    prepend: Vec<u8>,
) -> Result<(), String> {
    handle_tcp_connect_inner(local_stream, target_addr, req_tx, metrics, Some(prepend)).await
}

/// TCP CONNECT 代理内部实现
///
/// # 参数
/// - `prepend`: 建 QUIC 流后立即发送的首包数据（普通 HTTP 代理的请求头）
async fn handle_tcp_connect_inner(
    mut local_stream: TcpStream,
    target_addr: Address,
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    metrics: Arc<Metrics>,
    prepend: Option<Vec<u8>>,
) -> Result<(), String> {
    tracing::debug!(?target_addr, "TCP CONNECT 代理开始");

    // 1. 打开 QUIC 双向流
    let stream_id = request_open_bi_stream(&req_tx).await?;

    // 2. 发送 TUIC Connect 命令（含目标地址）+ 首包数据（如有）
    //    Connect 命令与首包合并在一次写入：服务端 leftover 解析自然拿到首包
    let mut wire_data = Command::Connect { addr: target_addr }.encode_to_vec();
    if let Some(p) = &prepend {
        wire_data.extend_from_slice(p);
    }
    let cmd_data = bytes::Bytes::from(wire_data);
    request_stream_write(&req_tx, stream_id, cmd_data).await?;

    // 3. 双向桥接：本地 TCP ↔ QUIC 流
    // 用 TcpStream::split 拆分读写半，避免 move 冲突
    let (tcp_read, mut tcp_write) = local_stream.into_split();
    let req_tx_up = req_tx.clone();
    let req_tx_down = req_tx.clone();
    let metrics_up = metrics.clone();
    let metrics_down = metrics.clone();

    // 上行任务：读取本地 TCP 数据 → 写入 QUIC 流
    let stream_id_up = stream_id;
    let up_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut tcp_read = tcp_read;
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    // 本地连接关闭（EOF），发 FIN 到 QUIC 流
                    let _ = request_stream_finish(&req_tx_up, stream_id_up).await;
                    break;
                }
                Ok(n) => {
                    let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                    match request_stream_write(&req_tx_up, stream_id_up, data).await {
                        Ok(written) => {
                            metrics_up.add_tx(written as u64);
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "QUIC 流写入失败，上行任务结束");
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "本地 TCP 读取失败");
                    let _ = request_stream_reset(&req_tx_up, stream_id_up, 1).await;
                    break;
                }
            }
        }
    });

    // 下行任务：从 QUIC 流读取数据 → 写入本地 TCP
    // v2：StreamRead 无数据时在 driver 内挂起等待（pending reply），
    // 有数据立即返回，消除旧版 10ms 轮询延迟
    let down_handle = tokio::spawn(async move {
        loop {
            match request_stream_read(&req_tx_down, stream_id).await {
                Ok(Some(data)) => {
                    metrics_down.add_rx(data.len() as u64);
                    // 写入本地 TCP 流
                    if let Err(e) = tcp_write.write_all(&data).await {
                        tracing::debug!(error = %e, "本地 TCP 写入失败");
                        break;
                    }
                }
                Ok(None) => {
                    // QUIC 流结束（FIN）
                    tracing::debug!("QUIC 流结束");
                    break;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "QUIC 流读取失败");
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
    Ok(())
}

/// 处理 UDP ASSOCIATE 代理（SOCKS5 UDP ASSOCIATE）
///
/// UDP 代理通过 QUIC bi-stream 发送 Packet 命令（可靠模式）。
/// 客户端从本地 SOCKS5 UDP 中继 socket 收发数据报。
pub async fn handle_udp_associate(
    _local_stream: TcpStream,
    _initial_addr: Address,
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    tracing::debug!("UDP ASSOCIATE 代理开始");

    // UDP 代理实现：
    // 1. 客户端创建本地 UDP socket 用于 SOCKS5 UDP 中继
    // 2. 打开一条 QUIC bi-stream 作为 UDP 会话通道
    // 3. 从本地 UDP socket 读数据报 → 封装为 Packet 命令 → 写入 QUIC 流
    // 4. 从 QUIC 流读 Packet 命令 → 解析 payload → 写入本地 UDP socket

    // 简化实现：UDP 代理在当前阶段先占位
    // 完整实现需要：
    // - 创建本地 UDP socket
    // - 分配 assoc_id
    // - 分片大包（>1300B）
    // - 重组分片

    // TODO: 完整 UDP 代理实现
    tracing::warn!("UDP 代理尚未完整实现（当前阶段占位）");
    metrics.dec_sessions();
    Ok(())
}

// === 驱动器请求封装 ===

/// 请求打开双向流
async fn request_open_bi_stream(
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
) -> Result<quinn_proto::StreamId, String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    req_tx
        .send(DriverRequest::OpenBiStream { reply: reply_tx })
        .map_err(|_| "驱动器通道关闭".to_string())?;

    reply_rx
        .await
        .map_err(|_| "驱动器回复通道关闭".to_string())?
        .map_err(|e| format!("打开双向流失败: {}", e))
}

/// 请求写入流数据
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
