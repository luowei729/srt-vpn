//! client/proxy.rs — 代理逻辑（TCP → 隧道）
//!
//! 设计决策（Q5/Q14/Q18）：
//! - TCP 流量转封装进 SRT 隧道（SRT 底层 UDP，TCP 语义经复用层保持）
//! - 支持半关闭（FIN 单向传播，P1 就支持）
//! - 数据流：客户端 TCP 流 → 复用层 Data 帧 → TS 封装 → SRT → 服务器 → 目标
//!
//! 流程：
//! 1. 分配会话 ID + 发 Open 帧（携带目标地址）
//! 2. 回复 SOCKS5 CONNECT 成功
//! 3. 双向转发：客户端流 ↔ 隧道 Data 帧
//! 4. 半关闭：客户端 EOF → Fin 帧（不关隧道会话接收侧）
//! 5. 会话结束：Close 帧

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::srt::connection::SrtConnection;
use crate::tunnel::dispatch::{SessionRegistry, TunnelSession};
use crate::tunnel::multiplex::MuxEncoder;
use crate::tunnel::FrameType;

/// 协议类型常量（Open 帧载荷）
const PROTO_TCP: u8 = 0;

/// 启动 TCP 转发（客户端 SOCKS5 连接 → 隧道）
///
/// 完整实现（P1）：
/// 1. 分配会话 ID 并发送 Open 帧（携带目标地址）
/// 2. 回复 SOCKS5 CONNECT 成功
/// 3. 双向转发：客户端流 ↔ 隧道 Data 帧
/// 4. 半关闭：客户端 EOF → Fin 帧（不关闭隧道会话接收侧）
/// 5. 会话结束：Close 帧
pub async fn start_tcp_forward(
    client: TcpStream,
    dst: String,
    dst_port: u16,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
) -> Result<(), String> {
    // SOCKS5 成功回复（绑定地址为本地地址）
    let reply = vec![0x05, super::socks5::REP_SUCCESS, 0x00, 0x01, 127, 0, 0, 1, 0, 0];
    start_forward_with_reply(client, dst, dst_port, conn, mux_enc, registry, &reply, &[]).await
}

/// 建立隧道会话 + 双向透传（SOCKS5 与 HTTP 代理共用，2026-08-19 新增）
///
/// - 建隧道：分配会话 + 发 Open 帧（携带目标地址）
/// - 成功后向客户端写 reply（SOCKS5 的 9 字节 / HTTP 的 "HTTP/1.1 200 ..."）
/// - 双向透传：客户端流 ↔ 隧道 Data 帧
/// - 半关闭：客户端 EOF → Fin 帧；对端 FIN → 半关闭
/// - 会话结束：Close 帧
pub async fn start_forward_with_reply(
    mut client: TcpStream,
    dst: String,
    dst_port: u16,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
    reply: &[u8],
    prepend: &[u8],
) -> Result<(), String> {
    // 1. 分配会话 ID + 接收通道
    let (session_id, rx) = registry.allocate();
    let mut session = TunnelSession::new(session_id, rx, conn, mux_enc, registry.clone());

    tracing::info!(session = session_id, dst = %format!("{dst}:{dst_port}"), "分配隧道会话");

    // 2. 发送 Open 帧通知服务器建立到目标的连接
    session.send_open(PROTO_TCP, &dst, dst_port).await?;

    // 3. 回复成功（SOCKS5 CONNECT 成功 / HTTP 200 Connection established）
    //    注：普通 HTTP 代理 reply 为空（不回复，等目标响应转发回来）
    if !reply.is_empty() {
        client
            .write_all(reply)
            .await
            .map_err(|e| format!("写 CONNECT 响应失败: {e}"))?;
    }

    // 4. 写已预读的数据（HTTP 请求头 / CONNECT 后的 TLS 数据）到隧道
    //    （普通 HTTP 代理把请求头透传；SOCKS5 为空；CONNECT 透传已缓存的 TLS 字节）
    if !prepend.is_empty() {
        session.send_data_batch(prepend).await?;
    }

    // 5. 双向转发：
    //    - 客户端读 → Data 帧 → 隧道
    //    - 隧道收 → 客户端写
    //    用 tokio::select! 同时监听两个方向
    //    缓冲 32KB（原 4KB）：一次读更多数据，减少高频小包（169B 分片）的调度开销，
    //    并让 send_data_batch 一次编码更多分片后批量投递（带宽优化 2026-08-19）
    let mut client_buf = [0u8; 32768];
    let mut client_eof = false; // 客户端是否已 EOF（半关闭标记）
    let session_eof = false; // 对端是否已 FIN（半关闭标记）
    let tx_total = std::sync::atomic::AtomicU64::new(0); // 客户端→隧道 累计
    let rx_total = std::sync::atomic::AtomicU64::new(0); // 隧道→客户端 累计

    loop {
        tokio::select! {
            // 方向 1：客户端 → 隧道
            read_result = client.read(&mut client_buf), if !client_eof => {
                match read_result {
                    Ok(0) => {
                        // 客户端 EOF：发送 Fin 帧（半关闭），停止读客户端
                        let _ = tx_total.load(std::sync::atomic::Ordering::Relaxed);
                        tracing::debug!(session = session_id, "客户端 EOF，发送 Fin");
                        session.send_fin().await?;
                        client_eof = true;
                        // 若对端也已 FIN，则关闭会话
                        if session_eof {
                            break;
                        }
                    }
                    Ok(n) => {
                        // 客户端数据 → 隧道 Data 帧（批量编码 + 批量投递）
                        tx_total.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);

                        session.send_data_batch(&client_buf[..n]).await?;
                    }
                    Err(e) => {
                        return Err(format!("读客户端数据失败: {e}"));
                    }
                }
            }
            // 方向 2：隧道 → 客户端
            recv_result = session.recv(), if !session_eof => {
                match recv_result {
                    Some(data) => {
                        // 隧道数据 → 客户端
                        rx_total.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        tracing::trace!(session = session_id, len = data.len(), "客户端写隧道数据到本地连接");
                        client.write_all(&data).await
                            .map_err(|e| format!("写客户端数据失败: {e}"))?;
                    }
                    None => {
                        // 隧道会话关闭（对端已关闭会话）
                        tracing::debug!(session = session_id, "隧道会话关闭");
                        break;
                    }
                }
            }
        }
    }

    // 5. 清理：关闭会话（发 Close 帧 + 移除注册表）
    let (txv, rxv) = (
        tx_total.load(std::sync::atomic::Ordering::Relaxed),
        rx_total.load(std::sync::atomic::Ordering::Relaxed),
    );
    tracing::info!(session = session_id, tx = txv, rx = rxv, "TCP 转发会话结束");
    let _ = session.send_control(FrameType::Close, &[]).await;
    client
        .shutdown()
        .await
        .map_err(|e| format!("关闭客户端连接失败: {e}"))?;
    Ok(())
}
