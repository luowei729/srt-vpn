//! server/forward.rs — 直连转发出口（P1）
//!
//! 设计决策（Q17）：
//! - P1：直连转发（TCP connect / UDP sendto），用户态实现
//! - P2：iptables masquerade + ip_forward（内核 NAT）
//!
//! 转发模型：
//! 客户端 Open 帧 → 建立到目标的 TCP 连接 → 双向转发（目标流 ↔ 隧道 Data 帧）
//!
//! 数据流（服务器侧）：
//! 隧道 Data 帧（会话 ID）→ SessionRegistry 路由 → forward 任务 → 目标连接
//! 目标连接数据 → TunnelSession.send_data → 隧道 → 客户端

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::srt::connection::SrtConnection;
use crate::tunnel::dispatch::{SessionRegistry, TunnelSession};
use crate::tunnel::multiplex::MuxEncoder;
use crate::tunnel::FrameType;

/// 协议类型常量（Open 帧载荷）
const PROTO_TCP: u8 = 0;
const PROTO_UDP: u8 = 1;

/// 会话打开请求载荷解析结果
#[derive(Debug, Clone)]
pub struct OpenRequest {
    /// 协议类型（0=TCP, 1=UDP）
    pub proto: u8,
    /// 目标主机（IP 或域名）
    pub host: String,
    /// 目标端口
    pub port: u16,
}

/// 解析 Open 帧载荷
/// 载荷格式：proto(1B) + host_len(1B) + host + port(2B BE)
pub fn parse_open_payload(payload: &[u8]) -> Option<OpenRequest> {
    if payload.len() < 4 {
        return None;
    }
    let proto = payload[0];
    let host_len = payload[1] as usize;
    if payload.len() < 2 + host_len + 2 {
        return None;
    }
    let host = String::from_utf8_lossy(&payload[2..2 + host_len]).into_owned();
    let port = u16::from_be_bytes([payload[2 + host_len], payload[3 + host_len]]);
    Some(OpenRequest { proto, host, port })
}

/// 处理 Open 请求：解析目标 → 建立直连转发 → 双向转发
///
/// 流程：
/// 1. 解析 Open 载荷（目标地址 + 端口 + 协议）
/// 2. 用已注册的接收通道建立隧道会话
/// 3. TCP：连接到目标，双向转发
/// 4. UDP：P2 实现
///
/// 注意：接收通道 rx 由调用方（listener.rs 的 Open 分支）预先注册，
/// 保证数据帧到达时能立即路由，避免时序竞态。
pub async fn handle_open_with_rx(
    session_id: u16,
    open_payload: &[u8],
    rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
) -> Result<(), String> {
    tracing::debug!(session = session_id, payload_len = open_payload.len(), "handle_open_with_rx 开始");
    // 1. 解析 Open 载荷
    let open = parse_open_payload(open_payload).ok_or("Open 载荷格式无效")?;
    tracing::info!(session = session_id, proto = open.proto, host = %open.host, port = open.port, "处理 Open 请求");

    // 2. 按协议分派
    match open.proto {
        PROTO_TCP => {
            start_tcp_forward(session_id, &open, rx, conn, mux_enc, registry).await
        }
        PROTO_UDP => {
            start_udp_forward(session_id, &open, rx, conn, mux_enc, registry).await
        }
        _ => Err(format!("未知协议类型: {}", open.proto)),
    }
}

/// UDP 直连转发（服务器端，2026-08-19 多目标版）
///
/// 设计（对应 SOCKS5 UDP ASSOCIATE 多目标场景）：
/// - Open 帧 proto=1；目标由每个 Data 帧的地址头动态指定（不是 Open 固定）
/// - 隧道 Data 帧负载格式：`[host_len(1B) + host + port(2B BE)][UDP payload]`
/// - 服务端单个共享 UdpSocket（未 connect），按目标 send_to；recv_from 得到源地址
/// - 目标响应回传格式相同：`[源host_len + 源host + 源port][payload]` → Data 帧
///
/// 约束：UDP payload + 地址头 ≤ FRAME_DATA_MAX(1301B)。大 UDP 数据报的重组为后续扩展。
async fn start_udp_forward(
    session_id: u16,
    _open: &OpenRequest, // 多目标：目标在每帧地址头，忽略 Open 的固定目标
    rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
) -> Result<(), String> {
    tracing::info!(session = session_id, "UDP 转发会话建立（多目标）");

    // 1. 创建共享 UDP socket（未 connect，支持多目标 send_to）
    let socket = std::sync::Arc::new(
        tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("UDP socket bind 失败: {e}"))?,
    );

    // 2. 用已注册的接收通道建立隧道会话
    let mut session = TunnelSession::new(session_id, rx, conn, mux_enc, registry.clone());

    // 3. 双向转发
    let mut udp_buf = [0u8; 65536];
    loop {
        tokio::select! {
            // 方向 1：隧道 → UDP 目标（按帧内地址头）
            recv_result = session.recv() => {
                match recv_result {
                    Some(data) => {
                        // 解析地址头 → (host, port, payload)
                        if let Some((host, port, payload)) = parse_udp_addr_header(&data) {
                            // 解析目标地址（lookup_host 接受 (host, port) 所有权，避免借用生命周期问题）
                            match tokio::net::lookup_host((host.as_str(), port)).await {
                                Ok(mut addrs) => {
                                    if let Some(addr) = addrs.next() {
                                        if let Err(e) = socket.send_to(payload, addr).await {
                                            tracing::debug!(session = session_id, error = %e, "UDP send_to 失败");
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(session = session_id, host = %host, port = port, error = %e, "UDP 目标解析失败");
                                }
                            }
                        } else {
                            tracing::debug!(session = session_id, "UDP 帧地址头无效");
                        }
                    }
                    None => {
                        tracing::debug!(session = session_id, "UDP 会话隧道侧关闭");
                        break;
                    }
                }
            }
            // 方向 2：UDP 目标响应 → 隧道（带源地址头）
            recv_from = socket.recv_from(&mut udp_buf) => {
                match recv_from {
                    Ok((len, src)) => {
                        // 封装 [源地址头][payload] 回传
                        let mut out = Vec::with_capacity(len + 40);
                        encode_udp_addr_header(&src, &mut out);
                        out.extend_from_slice(&udp_buf[..len]);
                        if let Err(e) = session.send_data(&out).await {
                            tracing::debug!(session = session_id, error = %e, "UDP 回传失败");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(session = session_id, error = %e, "UDP recv 失败");
                        break;
                    }
                }
            }
        }
    }

    // 4. 清理：关闭会话（发 Close 帧）
    tracing::debug!(session = session_id, "UDP 转发会话结束");
    let _ = session.send_control(FrameType::Close, &[]).await;
    Ok(())
}

/// 解析 UDP 地址头：`[host_len(1B) + host + port(2B BE)][payload]`
/// 返回 (host, port, payload)
pub fn parse_udp_addr_header(data: &[u8]) -> Option<(String, u16, &[u8])> {
    if data.len() < 3 {
        return None;
    }
    let host_len = data[0] as usize;
    if data.len() < 1 + host_len + 2 {
        return None;
    }
    let host = String::from_utf8_lossy(&data[1..1 + host_len]).into_owned();
    let port = u16::from_be_bytes([data[1 + host_len], data[2 + host_len]]);
    let payload = &data[3 + host_len..];
    Some((host, port, payload))
}

/// 编码 UDP 地址头（追加到 out）：`[host_len(1B) + host(IP字符串) + port(2B BE)]`
pub fn encode_udp_addr_header(addr: &std::net::SocketAddr, out: &mut Vec<u8>) {
    let host = addr.ip().to_string();
    let host_bytes = host.as_bytes();
    out.push(host_bytes.len() as u8);
    out.extend_from_slice(host_bytes);
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// TCP 直连转发（服务器端）
///
/// 完整实现：
/// 1. 连接到目标
/// 2. 双向转发：目标 TCP 流 ↔ 隧道 Data 帧
/// 3. 半关闭：目标 EOF → Fin 帧（不关隧道会话）
/// 4. 会话结束：Close 帧
pub async fn start_tcp_forward(
    session_id: u16,
    open: &OpenRequest,
    rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
) -> Result<(), String> {
    // 1. 连接目标（支持 IPv4/DNS）
    //    稳定性加固（2026-08-19）：connect 加 10s 超时，避免目标不可达时
    //    转发任务永久挂起（此前"连接目标超时"会话死循环导致服务端卡死的根因之一）
    let target = format!("{}:{}", open.host, open.port);
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&target),
    )
    .await
    .map_err(|_| format!("连接目标 {target} 超时"))?
    .map_err(|e| format!("连接目标 {target} 失败: {e}"))?;
    tracing::info!(session = session_id, target = %target, "TCP 转发会话建立");

    // 2. 用已注册的接收通道建立隧道会话（不再自行注册，避免竞态）
    let mut session = TunnelSession::new(session_id, rx, conn, mux_enc, registry.clone());

    // 3. 双向转发：
    //    - 目标读 → Data 帧 → 隧道
    //    - 隧道收 → 目标写
    //    缓冲 32KB（原 4KB）：一次读更多数据，让 send_data_batch 一次编码更多分片
    //    后批量投递，减少高频小包（169B 分片)的调度开销（带宽优化 2026-08-19）
    let mut target_buf = [0u8; 32768];
    let mut target_eof = false; // 目标 EOF（半关闭标记）
    let session_eof = false; // 对端 FIN（半关闭标记）
    let mut rx_bytes: u64 = 0; // 隧道→目标 累计字节（诊断）
    let mut tx_bytes: u64 = 0; // 目标→隧道 累计字节（诊断）

    // 稳定性加固（2026-08-19）：空闲看门狗。双向 N 秒内无任何数据活动则关闭会话，
    // 防止"目标侧 hang 住"的死会话永久占资源（此前服务端卡死/会话泄漏的根因）。
    // 每次有双向数据活动时重置看门狗（sleep 重新计时）。
    const IDLE_TIMEOUT_SECS: u64 = 300;
    let idle_duration = std::time::Duration::from_secs(IDLE_TIMEOUT_SECS);
    // 用 pin! 固定 Sleep（!Unpin），以便 select 借用 &mut 并在活动分支 reset
    let mut idle_watchdog = std::pin::pin!(tokio::time::sleep(idle_duration));

    loop {
        tokio::select! {
            // 看门狗：长时间无活动则退出（返回 Err 由上层清理会话）
            _ = &mut idle_watchdog => {
                tracing::warn!(session = session_id, idle_secs = IDLE_TIMEOUT_SECS, "转发会话空闲超时，关闭");
                return Err(format!("会话 {session_id} 空闲超时（>{}s）", IDLE_TIMEOUT_SECS));
            }
            // 方向 1：目标 → 隧道
            read_result = stream.read(&mut target_buf), if !target_eof => {
                match read_result {
                    Ok(0) => {
                        // 目标 EOF：发送 Fin 帧（半关闭）
                        tracing::debug!(session = session_id, tx_total = tx_bytes, "目标 EOF，发送 Fin");
                        session.send_fin().await?;
                        target_eof = true;
                        if session_eof {
                            break;
                        }
                    }
                    Ok(n) => {
                        // 目标数据 → 隧道 Data 帧（批量编码 + 批量投递）
                        tx_bytes += n as u64;
                        if cfg!(debug_assertions) {
                        }
                        if tx_bytes % 262144 < 4096 {
                            tracing::debug!(session = session_id, tx_total = tx_bytes, "目标→隧道 进度");
                        }
                        session.send_data_batch(&target_buf[..n]).await?;
                        // 有活动：重置看门狗
                        idle_watchdog.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                    }
                    Err(e) => {
                        return Err(format!("读目标数据失败: {e}"));
                    }
                }
            }
            // 方向 2：隧道 → 目标
            recv_result = session.recv(), if !session_eof => {
                match recv_result {
                    Some(data) => {
                        // 隧道数据 → 目标
                        rx_bytes += data.len() as u64;
                        if rx_bytes % 262144 < 4096 {
                            tracing::debug!(session = session_id, rx_total = rx_bytes, "隧道→目标 进度");
                        }
                        stream.write_all(&data).await
                            .map_err(|e| format!("写目标数据失败: {e}"))?;
                        // 有活动：重置看门狗
                        idle_watchdog.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                    }
                    None => {
                        // 隧道会话关闭（客户端关闭）
                        tracing::debug!(session = session_id, rx_total = rx_bytes, "隧道会话关闭");
                        break;
                    }
                }
            }
        }
    }

    // 4. 清理：关闭会话（发 Close 帧 + 移除注册表）
    tracing::debug!(session = session_id, "TCP 转发会话结束");
    let _ = session.send_control(FrameType::Close, &[]).await;
    stream
        .shutdown()
        .await
        .map_err(|e| format!("关闭目标连接失败: {e}"))?;
    Ok(())
}
