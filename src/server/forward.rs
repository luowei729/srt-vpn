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
use crate::tunnel::dispatch::{SessionEvent, SessionRegistry, TunnelSession};
use crate::tunnel::multiplex::{MuxEncoder, FRAME_DATA_MAX};
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
    rx: tokio::sync::mpsc::UnboundedReceiver<crate::tunnel::dispatch::SessionEvent>,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
) -> Result<(), String> {
    tracing::debug!(session = session_id, payload_len = open_payload.len(), "handle_open_with_rx 开始");
    // 1. 解析 Open 载荷
    //
    // 2026-08-20 修复（多线程上传带宽暴跌根因）：
    // 旧实现仅"正常结束"路径发 Close 帧，连接失败/读目标失败/RST/看门狗超时等
    // 异常路径直接 return Err 静默退出 -> 客户端不知道会话已死，继续向僵尸会话
    // 灌上传数据（实测故障时段单会话丢弃 1297 帧/分钟，隧道带宽被垃圾帧占满）。
    // 现在所有退出路径统一在外层兜底发 Close 帧（死前讣告），客户端收到后
    // 立即停止发送并释放会话 ID，杜绝僵尸会话。
    let open = match parse_open_payload(open_payload) {
        Some(o) => o,
        None => {
            let e = "Open 载荷格式无效";
            notify_session_closed(session_id, &conn, &mux_enc).await;
            return Err(e.to_string());
        }
    };
    tracing::info!(session = session_id, proto = open.proto, host = %open.host, port = open.port, "处理 Open 请求");

    // 2. 按协议分派（无论成功/失败/超时，外层统一发 Close 通知客户端）
    let result = match open.proto {
        PROTO_TCP => {
            start_tcp_forward(session_id, &open, rx, conn.clone(), mux_enc.clone(), registry).await
        }
        PROTO_UDP => {
            start_udp_forward(session_id, &open, rx, conn.clone(), mux_enc.clone(), registry).await
        }
        _ => Err(format!("未知协议类型: {}", open.proto)),
    };
    // 会话终结讣告：任何退出路径（含 Err）都通知客户端（幂等，客户端收到即清理）
    notify_session_closed(session_id, &conn, &mux_enc).await;
    result
}

/// 会话终结通知（发 Close 帧；连接已断则忽略失败）
///
/// 2026-08-20 新增：服务端会话死亡的唯一讣告出口。
/// 无论会话因何原因结束（目标 RST/超时/错误），客户端必须得知才能停止发送。
async fn notify_session_closed(session_id: u16, conn: &Arc<SrtConnection>, mux_enc: &Arc<MuxEncoder>) {
    let frame = mux_enc.encode_frame(FrameType::Close, session_id, 0, &[]);
    if let Err(e) = conn.send(frame) {
        // 隧道本身断开时发不出去（客户端整条隧道都在重建，会话随之清空），忽略
        tracing::debug!(session = session_id, error = %e, "发送会话 Close 讣告失败（隧道可能已断开）");
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
    rx: tokio::sync::mpsc::UnboundedReceiver<crate::tunnel::dispatch::SessionEvent>,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
) -> Result<(), String> {
    tracing::info!(session = session_id, "UDP 转发会话建立（多目标）");

    // 1. 创建共享 UDP socket（未 connect，支持多目标 send_to）
    //    H2 配套修复（2026-08-19）：按目标地址族选 socket--
    //    IPv4 socket（bind 0.0.0.0）无法向 IPv6 目标 send_to（实测 ::1 超时根因）。
    //    现懒创建两个 socket：首次遇到 v6 目标时补建 v6 socket；
    //    回包来源按地址族路由到对应 socket 的 recv 分支。
    let socket_v4 = std::sync::Arc::new(
        tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("UDP socket bind 失败: {e}"))?,
    );
    // v6 socket 懒创建（大多数场景只有 v4 流量，避免无谓占端口/句柄）
    let mut socket_v6: Option<std::sync::Arc<tokio::net::UdpSocket>> = None;

    // 2. 用已注册的接收通道建立隧道会话
    let mut session = TunnelSession::new(session_id, rx, conn, mux_enc, registry.clone());

    // 3. 双向转发（大包分片 + 重组）
    //
    // 2026-08-19 审查修复（F3 UDP 空闲看门狗 + B2 事件接收）：
    // - 增加空闲看门狗：双向 N 秒无任何数据活动则关闭会话（此前 UDP 会话无超时，
    //   客户端静默/异常断开时服务器侧 UDP 会话 + 注册表条目永久存在——会话泄漏隐患）
    // - 改用 recv_event：收到 Fin/Close 事件正常结束（对端关闭时立即清理）
    const UDP_IDLE_TIMEOUT_SECS: u64 = 300;
    let idle_duration = std::time::Duration::from_secs(UDP_IDLE_TIMEOUT_SECS);
    let mut idle_watchdog = std::pin::pin!(tokio::time::sleep(idle_duration));
    let mut udp_buf = [0u8; 65536];
    // H2：v6 回包独立缓冲（select 两分支不能同时可变借用同一 buf）
    let mut udp_buf_v6 = [0u8; 65536];
    let mut reassembler = UdpReassembler::new();
    // M3：活动计数，每 64 次收包顺带做一次重组状态过期清理（摊薄成本）
    let mut activity_count: u64 = 0;
    loop {
        tokio::select! {
            // 看门狗：长时间无活动则退出（清理泄漏会话）
            _ = &mut idle_watchdog => {
                tracing::warn!(session = session_id, idle_secs = UDP_IDLE_TIMEOUT_SECS, "UDP 转发会话空闲超时，关闭");
                break;
            }
            // 方向 1：隧道 -> UDP 目标（按帧内地址头，大包分片自动重组）
            recv_result = session.recv_event() => {
                match recv_result {
                    Some(SessionEvent::Data(data)) => {
                        // M3：周期性清理过期的重组残留状态（防泄漏）
                        activity_count += 1;
                        if activity_count % 64 == 0 {
                            reassembler.cleanup_expired();
                        }
                        // 输入重组器：小包直接出，分片积累到重组完成才出
                        if let Some(full) = reassembler.push(&data) {
                            // 解析地址头 → (host, port, payload)
                            if let Some((host, port, payload)) = parse_udp_addr_header(&full) {
                                // P0 2026-08-23：IP字面量快路径（避免每包DNS，speedtest上传0时STUN风暴放大）
                                let resolved: Option<std::net::SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                                    Some(std::net::SocketAddr::new(ip, port))
                                } else {
                                    match tokio::net::lookup_host((host.as_str(), port)).await {
                                        Ok(mut addrs) => addrs.next(),
                                        Err(e) => {
                                            tracing::debug!(session = session_id, host = %host, port = port, error = %e, "UDP 目标解析失败");
                                            None
                                        }
                                    }
                                };
                                if let Some(addr) = resolved {
                                    // H2 配套修复（2026-08-19）：按目标地址族选 socket
                                    // （v4-only socket 无法向 v6 目标 send_to，实测 ::1 超时根因）
                                    let sock = if addr.is_ipv4() {
                                        socket_v4.clone()
                                    } else {
                                        match &socket_v6 {
                                            Some(s) => s.clone(),
                                            None => {
                                                match tokio::net::UdpSocket::bind("[::]:0").await {
                                                    Ok(s) => {
                                                        let s = std::sync::Arc::new(s);
                                                        socket_v6 = Some(s.clone());
                                                        s
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(session = session_id, error = %e, "IPv6 UDP socket 创建失败（v6 目标不可达）");
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                    };
                                    if let Err(e) = sock.send_to(payload, addr).await {
                                        tracing::debug!(session = session_id, error = %e, "UDP send_to 失败");
                                    }
                                }
                            } else {
                                tracing::debug!(session = session_id, "UDP 帧地址头无效");
                            }
                        }
                        // 有活动：重置看门狗
                        idle_watchdog.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                    }
                    Some(SessionEvent::Fin) => {
                        // 对端半关闭：UDP 无连接语义，视为结束
                        tracing::debug!(session = session_id, "UDP 会话收到对端 FIN，结束");
                        break;
                    }
                    Some(SessionEvent::Close) => {
                        tracing::debug!(session = session_id, "UDP 会话收到对端 Close");
                        break;
                    }
                    None => {
                        tracing::debug!(session = session_id, "UDP 会话隧道侧关闭");
                        break;
                    }
                }
            }
            // 方向 2：UDP 目标响应 → 隧道（带源地址头；大包自动分片）
            // H2 配套（2026-08-19）：v4 socket 恒监听；v6 socket 存在时并入监听
            recv_from = socket_v4.recv_from(&mut udp_buf) => {
                match recv_from {
                    Ok((len, src)) => {
                        // 封装 [源地址头][payload]
                        let mut header = Vec::with_capacity(40);
                        encode_udp_addr_header(&src, &mut header);
                        // 按大小自动分片（小包单帧原样，大包拆多帧）
                        let frames = split_udp_frames(&header, &udp_buf[..len]);
                        for frame in frames {
                            // v0.5.2：回传方向改走不可靠通道（QUIC DATAGRAM 语义），
                            // 与客户端→隧道方向对称，丢包链路下 UDP 延时不被重传拖高
                            if let Err(e) = session.send_unreliable(&frame).await {
                                tracing::debug!(session = session_id, error = %e, "UDP 回传失败");
                                break;
                            }
                        }
                        // 有活动：重置看门狗
                        idle_watchdog.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                    }
                    Err(e) => {
                        tracing::debug!(session = session_id, error = %e, "UDP recv 失败");
                        break;
                    }
                }
            }
            // H2：v6 socket 回包分支（socket_v6 未创建时该 future 永久 pending，不触发）
            recv_from_v6 = async {
                match socket_v6.as_ref() {
                    Some(s) => s.recv_from(&mut udp_buf_v6).await,
                    None => std::future::pending().await,
                }
            } => {
                match recv_from_v6 {
                    Ok((len, src)) => {
                        // v6 源回包：同 v4 路径封装回传
                        let mut header = Vec::with_capacity(64);
                        encode_udp_addr_header(&src, &mut header);
                        let frames = split_udp_frames(&header, &udp_buf_v6[..len]);
                        for frame in frames {
                            // v0.5.2：v6 回包同样走不可靠通道（与 v4 对称）
                            if let Err(e) = session.send_unreliable(&frame).await {
                                tracing::debug!(session = session_id, error = %e, "UDP 回传失败（v6）");
                                break;
                            }
                        }
                        idle_watchdog.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                    }
                    Err(e) => {
                        tracing::debug!(session = session_id, error = %e, "UDP recv 失败（v6）");
                        break;
                    }
                }
            }
        }
    }

    // 4. 清理：会话结束（Close 讣告由外层 handle_open_with_rx 统一发送，2026-08-20）
    tracing::debug!(session = session_id, "UDP 转发会话结束");
    Ok(())
}

/// 解析 UDP 地址头：`[host_len(1B) + host + port(2B BE)][payload]`
/// 返回 (host, port, payload)
/// host 是字符串形式（IPv4 / IPv6 / 域名均可，H2 修复后支持全类型）
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

/// 编码 UDP 地址头（追加到 out）：`[host_len(1B) + host字符串 + port(2B BE)]`
/// H2 修复（2026-08-19）：host 直接按字符串编码（IPv4/IPv6/域名统一支持）。
/// 旧版只接受 SocketAddr（IPv4/IPv6），域名目标在客户端侧被丢成 0.0.0.0。
pub fn encode_udp_addr_header_host(host: &str, port: u16, out: &mut Vec<u8>) {
    let host_bytes = host.as_bytes();
    out.push(host_bytes.len() as u8);
    out.extend_from_slice(host_bytes);
    out.extend_from_slice(&port.to_be_bytes());
}

/// 编码 UDP 地址头（SocketAddr 便捷版，内部转字符串）
pub fn encode_udp_addr_header(addr: &std::net::SocketAddr, out: &mut Vec<u8>) {
    encode_udp_addr_header_host(&addr.ip().to_string(), addr.port(), out);
}

// ─────────────────────────────────────────────────────────────────────────
// UDP 大包分片协议（2026-08-19 多目标版扩展）
//
// 背景：单隧道帧 payload 上限 FRAME_DATA_MAX=1301B（SRT 原生 payload 1316 -
// 复用层帧头 15B）。UDP 数据报最大 65507B，超出单帧承载时必须分片传输。
//
// 协议格式（Data 帧负载，区分大小包）：
// - 小包（可单帧承载）：
//     [host_len(1B) + host + port(2B BE)][payload]
//   ↑ 与旧版完全兼容（无分片标记 0xFF 前缀）
// - 大包（分片传输，**每片都带地址头**）：
//     [地址头][0xFF][total_len(u16 BE)][idx(1B)][total(1B)][payload片段]
//
// 说明：
// - 0xFF 作为"分片标记"：host_len 字段合法范围 1..=253（IP 字符串最长 45B/域名最长 253B），
//   0xFF=255 不可能与真实 host_len 冲突，可安全用作分片标记
// - 每片都带地址头：保证重组器能按 (host,port) 解析 key 聚合分片，无需额外分片组 ID；
//   代价是每片多 ~12B 地址头开销，换取协议简单可靠
// - total_len：完整 UDP 数据报的 payload 总长（不含地址头），用于重组校验
// - idx：分片序号（0 起），total：总分片数。单帧最多 255 片，理论支持最大
//   255*(1301-5-地址头) ≈ 数百 KB，远超 UDP 65507B 上限，够用
// - SRT 隧道保证帧有序可靠到达（单 SRT 连接 + 消息模式），接收端只需按 idx 顺序拼接
//
// 兼容性：旧版（无分片支持）客户端收到 0xFF 分片标记会解析失败并丢弃该帧，
// 不影响协议整体可用性（大包丢、小包通）。本实现同时兼容新旧。
// ─────────────────────────────────────────────────────────────────────────

/// 分片标记字节（见协议说明，与 host_len 合法范围不冲突）
const UDP_FRAG_MARK: u8 = 0xFF;

/// 分片结果：从"地址头 + 完整 UDP payload"拆分出多个单帧负载
///
/// 输入：地址头 + 完整 UDP payload
/// 输出（每片都带地址头，保证重组 key 可解析）：
/// - 小包：原样单帧返回
/// - 大包：每片 `[地址头][0xFF][len BE][idx][total]` + payload 片段
pub fn split_udp_frames(addr_header: &[u8], payload: &[u8]) -> Vec<Vec<u8>> {
    // 大包判定：地址头 + 分片头 5B + 至少 1B payload 超出单帧 → 需分片
    let header_and_frag_overhead = addr_header.len() + 5;
    if payload.len() + header_and_frag_overhead <= FRAME_DATA_MAX {
        // 小包：原样（地址头 + payload）单帧
        let mut frame = Vec::with_capacity(addr_header.len() + payload.len());
        frame.extend_from_slice(addr_header);
        frame.extend_from_slice(payload);
        return vec![frame];
    }

    // 大包：分片（每片容量 = 单帧 - 地址头 - 分片头 5B）
    let per_part = FRAME_DATA_MAX - addr_header.len() - 5;
    let total_len = payload.len();
    debug_assert!(total_len <= u16::MAX as usize, "UDP payload 超长");
    let total_parts = payload.len().div_ceil(per_part);
    debug_assert!(total_parts <= u8::MAX as usize, "分片数超 255");

    let mut frames = Vec::with_capacity(total_parts);
    for idx in 0..total_parts {
        let start = idx * per_part;
        let end = (start + per_part).min(total_len);
        let mut part = Vec::with_capacity(FRAME_DATA_MAX);
        part.extend_from_slice(addr_header);
        part.push(UDP_FRAG_MARK);
        part.extend_from_slice(&(total_len as u16).to_be_bytes());
        part.push(idx as u8);
        part.push(total_parts as u8);
        part.extend_from_slice(&payload[start..end]);
        frames.push(part);
    }
    frames
}

/// UDP 分片重组器（接收方向）
///
/// 将多个分片帧重组为完整 UDP 数据报（含地址头）。
/// SRT 隧道有序可靠，理论上不会乱序，但防御性实现仍支持乱序到达。
pub struct UdpReassembler {
    /// 进行中的重组缓冲区：目标 key → 重组状态
    pending: std::collections::HashMap<(String, u16), ReasmState>,
    /// 每个重组状态的创建时间（用于过期清理，M3 修复 2026-08-19）
    /// 与 pending 同 key 同生命周期（entry/remove 同步维护）
    created_at: std::collections::HashMap<(String, u16), std::time::Instant>,
}

/// 不完整重组状态的保留时长（M3：对端发一半崩溃时，残留状态过期清理防泄漏）
const REASM_EXPIRY_SECS: u64 = 30;

/// 单个进行中重组的完整状态
struct ReasmState {
    /// 完整 UDP payload 总长（协议字段 total_len）
    total_len: usize,
    /// 总分片数
    total_parts: u8,
    /// 已收到的分片（Option 表示未到）
    parts: Vec<Option<Vec<u8>>>,
    /// 已收到片数
    received: usize,
    /// 已收集的地址头（从首片提取）
    addr_header: Vec<u8>,
}

impl UdpReassembler {
    /// 创建重组器
    pub fn new() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
            created_at: std::collections::HashMap::new(),
        }
    }

    /// 过期清理（M3 修复 2026-08-19）：
    /// 移除超过 REASM_EXPIRY_SECS 仍未重组完成的状态。
    /// 由转发循环周期调用（看门狗重置时机顺带清理即可），防止对端
    /// 发送一半崩溃时残留状态缓慢泄漏。返回清理的数量。
    pub fn cleanup_expired(&mut self) -> usize {
        let now = std::time::Instant::now();
        let expired: Vec<(String, u16)> = self
            .created_at
            .iter()
            .filter(|(_, t)| now.duration_since(**t) > std::time::Duration::from_secs(REASM_EXPIRY_SECS))
            .map(|(k, _)| k.clone())
            .collect();
        let n = expired.len();
        for k in &expired {
            self.pending.remove(k);
            self.created_at.remove(k);
        }
        n
    }

    /// 输入一个隧道 Data 帧负载，返回可投递的完整 UDP 数据报（含地址头）
    ///
    /// - 小包（无 0xFF 分片标记）：立即返回（兼容旧协议）
    /// - 分片：返回 None（继续收片）；重组完成后返回 Some(完整数据报)
    /// - 异常分片（非法参数/超时）：丢弃该帧返回 None
    pub fn push(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        // 解析地址头（首片必有；若分片标记位于地址头解析后的位置则继续）
        let (host, port, rest) = parse_udp_addr_header(frame)?;
        if rest.is_empty() {
            // 无 payload：非法帧，丢弃
            return None;
        }
        if rest[0] != UDP_FRAG_MARK {
            // 小包：完整数据报（地址头 + payload）
            return Some(frame.to_vec());
        }
        // 分片帧：解析分片头
        if rest.len() < 5 {
            return None; // 分片头不完整
        }
        let total_len = u16::from_be_bytes([rest[1], rest[2]]) as usize;
        let idx = rest[3] as usize;
        let total = rest[4] as usize;
        if total == 0 || total > 255 || idx >= total {
            return None; // 非法参数
        }
        // 分片 payload（首片含地址头后的数据，后续片为纯数据）
        let frag_payload = &rest[5..];
        if total_len == 0 || total_len > 65535 {
            return None;
        }

        // 关键路径（index=0 或首次）：初始化重组状态
        let key = (host.clone(), port);
        let state = self.pending.entry(key.clone()).or_insert_with(|| {
            // 新建重组状态时记录创建时间（M3 过期清理用）
            self.created_at.insert(key.clone(), std::time::Instant::now());
            ReasmState {
                total_len,
                total_parts: total as u8,
                parts: vec![None; total],
                received: 0,
                addr_header: Vec::new(),
            }
        });

        // 防御：同一 key 的新分片组（total_len/total 变化）→ 重置
        if state.total_len != total_len || state.total_parts as usize != total {
            state.total_len = total_len;
            state.total_parts = total as u8;
            state.parts = vec![None; total];
            state.received = 0;
            state.addr_header.clear();
        }

        // 首片提取地址头（地址头 = [host_len + host + port] 3+len 字节）
        if idx == 0 {
            let header_len = 1 + host.len() + 2;
            state.addr_header = frame[..header_len].to_vec();
        }

        if state.parts[idx].is_none() {
            state.parts[idx] = Some(frag_payload.to_vec());
            state.received += 1;
        }

        // 重组完成检查
        if state.received == total {
            let mut full = Vec::with_capacity(state.total_len + state.addr_header.len());
            full.extend_from_slice(&state.addr_header);
            for part in &state.parts {
                let p = part.as_ref()?;
                full.extend_from_slice(p);
            }
            self.pending.remove(&key);
            self.created_at.remove(&key); // 同步清理时间记录（M3）
            Some(full)
        } else {
            None
        }
    }
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
    rx: tokio::sync::mpsc::UnboundedReceiver<crate::tunnel::dispatch::SessionEvent>,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
) -> Result<(), String> {
    // 1. 连接目标（支持 IPv4/DNS）
    //    稳定性加固（2026-08-19）：connect 加 10s 超时，避免目标不可达时
    //    转发任务永久挂起（此前"连接目标超时"会话死循环导致服务端卡死的根因之一）
    //    P0 2026-08-23：10s→3s 快失败（speedtest上传0时多并发Open 10s占会话，隧道被垃圾会话占满）
    let target = format!("{}:{}", open.host, open.port);
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
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
    //
    //    2026-08-19 审查修复（B2 半关闭传播）：
    //    - 目标 EOF → send_fin()（单向 FIN：告知对端不再发数据，本端仍收）
    //    - 收到对端 SessionEvent::Fin → shutdown 目标写侧（对端不再发，本端仍可发）
    //    - 双向 FIN 或收到 Close → 结束会话
    let mut target_buf = [0u8; 32768];
    let mut target_eof = false; // 目标 EOF（本端发送侧关闭标记）
    let mut peer_fin = false;   // 对端 Fin（对端发送侧关闭标记）
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
                        if peer_fin {
                            break;
                        }
                    }
                    Ok(n) => {
                        // 目标数据 → 隧道 Data 帧（批量编码 + 批量投递）
                        tx_bytes += n as u64;
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
            recv_result = session.recv_event(), if !peer_fin => {
                match recv_result {
                    Some(SessionEvent::Data(data)) => {
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
                    Some(SessionEvent::Fin) => {
                        // 对端半关闭：不再有数据来，shutdown 目标写侧（本端仍可发）
                        tracing::debug!(session = session_id, "对端 FIN，shutdown 目标写侧");
                        let _ = stream.shutdown().await;
                        peer_fin = true;
                        // 若本端也已 EOF，则关闭会话
                        if target_eof {
                            break;
                        }
                    }
                    Some(SessionEvent::Close) => {
                        // 对端完全关闭会话
                        tracing::debug!(session = session_id, "对端关闭会话");
                        break;
                    }
                    None => {
                        // 隧道会话通道关闭（客户端连接断开）
                        tracing::debug!(session = session_id, rx_total = rx_bytes, "隧道会话关闭");
                        break;
                    }
                }
            }
        }
    }

    // 4. 清理：会话结束（Close 讣告由外层 handle_open_with_rx 统一发送，2026-08-20）
    tracing::debug!(session = session_id, "TCP 转发会话结束");
    stream
        .shutdown()
        .await
        .map_err(|e| format!("关闭目标连接失败: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 IPv4 地址头（模拟 encode_udp_addr_header 输出）
    fn mk_header(host: &str, port: u16) -> Vec<u8> {
        let mut h = Vec::new();
        h.push(host.len() as u8);
        h.extend_from_slice(host.as_bytes());
        h.extend_from_slice(&port.to_be_bytes());
        h
    }

    #[test]
    fn test_split_small_packet_single_frame() {
        // 小包（≤ 单帧承载）：原样单帧返回（兼容旧协议）
        let header = mk_header("127.0.0.1", 9900);
        let payload = b"hello udp";
        let frames = split_udp_frames(&header, payload);
        assert_eq!(frames.len(), 1);
        // 帧 = 地址头 + payload，无分片标记
        let mut expect = header.clone();
        expect.extend_from_slice(payload);
        assert_eq!(frames[0], expect);
    }

    #[test]
    fn test_split_large_packet_multiple_frames() {
        // 大包（2000B）：分片为多帧，且每帧 ≤ FRAME_DATA_MAX
        let header = mk_header("127.0.0.1", 9900);
        let payload = vec![0xABu8; 2000];
        let frames = split_udp_frames(&header, &payload);
        assert!(frames.len() > 1, "大包应分片");
        for f in &frames {
            assert!(f.len() <= FRAME_DATA_MAX, "单帧超限: {}", f.len());
        }
        // 每片都带地址头，分片标记在地址头之后（地址头 = 1 + 9 + 2 = 12B）
        let header_len = 1 + 9 + 2;
        for f in &frames {
            assert_eq!(f[header_len], UDP_FRAG_MARK, "分片帧应有分片标记");
            assert_eq!(&f[..header_len], &header[..], "每片应携带相同地址头");
        }
    }

    #[test]
    fn test_reassemble_small_packet() {
        // 小包直接输出（不进入重组状态机）
        let header = mk_header("127.0.0.1", 9900);
        let payload = b"small";
        let mut frame = header.clone();
        frame.extend_from_slice(payload);
        let mut reasm = UdpReassembler::new();
        let out = reasm.push(&frame).expect("小包应直接输出");
        assert_eq!(out, frame);
        assert!(reasm.pending.is_empty());
    }

    #[test]
    fn test_reassemble_large_packet() {
        // 大包：分片 → 重组 → 完整数据报（地址头 + 全部 payload）
        let header = mk_header("127.0.0.1", 9900);
        let payload: Vec<u8> = (0..3000u16).map(|i| (i % 251) as u8).collect();
        let frames = split_udp_frames(&header, &payload);
        assert!(frames.len() > 1);

        let mut reasm = UdpReassembler::new();
        let mut result: Option<Vec<u8>> = None;
        for f in &frames {
            if let Some(full) = reasm.push(f) {
                result = Some(full);
            }
        }
        let full = result.expect("重组应完成");
        // 数据报 = 地址头 + 完整 payload（顺序/内容一致）
        assert_eq!(&full[..header.len()], &header[..]);
        assert_eq!(&full[header.len()..], &payload[..]);
        assert!(reasm.pending.is_empty(), "重组完成后清理");
    }

    #[test]
    fn test_reassemble_out_of_order() {
        // 防御性乱序重组：反序投递分片仍能正确重组
        let header = mk_header("127.0.0.1", 9900);
        let payload: Vec<u8> = (0..4000u16).map(|i| (i % 253) as u8).collect();
        let mut frames = split_udp_frames(&header, &payload);
        assert!(frames.len() > 2, "4000B 应分 ≥3 片，实际 {}", frames.len());
        frames.reverse(); // 乱序

        let mut reasm = UdpReassembler::new();
        let mut result: Option<Vec<u8>> = None;
        for f in &frames {
            if let Some(full) = reasm.push(f) {
                result = Some(full);
            }
        }
        let full = result.expect("乱序重组应完成");
        assert_eq!(&full[header.len()..], &payload[..]);
    }

    #[test]
    fn test_multi_target_interleaved_reassembly() {
        // 多目标交错分片：两个不同 (host,port) 的大包同时重组互不干扰
        let h1 = mk_header("127.0.0.1", 9900);
        let h2 = mk_header("10.0.0.2", 9901);
        let p1: Vec<u8> = vec![1u8; 2000];
        let p2: Vec<u8> = vec![2u8; 2100];

        let f1 = split_udp_frames(&h1, &p1);
        let f2 = split_udp_frames(&h2, &p2);

        let mut reasm = UdpReassembler::new();
        // 交错投递：f1[0], f2[0], f1[1], f2[1], ...
        let max = f1.len().max(f2.len());
        let mut r1: Option<Vec<u8>> = None;
        let mut r2: Option<Vec<u8>> = None;
        for i in 0..max {
            if let Some(f) = f1.get(i) {
                if let Some(full) = reasm.push(f) {
                    r1 = Some(full);
                }
            }
            if let Some(f) = f2.get(i) {
                if let Some(full) = reasm.push(f) {
                    r2 = Some(full);
                }
            }
        }
        let full1 = r1.expect("目标1重组");
        let full2 = r2.expect("目标2重组");
        assert_eq!(&full1[h1.len()..], &p1[..]);
        assert_eq!(&full2[h2.len()..], &p2[..]);
    }

    #[test]
    fn test_invalid_frag_dropped() {
        // 非法分片（total=0 / idx 越界）应被丢弃，不 panic
        let mut reasm = UdpReassembler::new();
        // 地址头 + 分片标记 + total_len + idx=0 + total=0（非法）
        let mut bad = mk_header("127.0.0.1", 9900);
        bad.extend_from_slice(&[UDP_FRAG_MARK, 0x00, 0x10, 0x00, 0x00]); // total=0 非法
        assert!(reasm.push(&bad).is_none());

        // 分片头不完整（长度不足 5）
        let mut bad2 = mk_header("127.0.0.1", 9900);
        bad2.extend_from_slice(&[UDP_FRAG_MARK, 0x00]);
        assert!(reasm.push(&bad2).is_none());
    }

    #[test]
    fn test_parse_udp_addr_header_roundtrip() {
        // 地址头编解码往返
        let addr: std::net::SocketAddr = "127.0.0.1:9900".parse().unwrap();
        let mut encoded = Vec::new();
        encode_udp_addr_header(&addr, &mut encoded);
        let (host, port, payload) = parse_udp_addr_header(&encoded).unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9900);
        assert!(payload.is_empty());

        // 带 payload
        let mut encoded2 = Vec::new();
        encode_udp_addr_header(&addr, &mut encoded2);
        encoded2.extend_from_slice(b"data");
        let (_, _, payload) = parse_udp_addr_header(&encoded2).unwrap();
        assert_eq!(payload, b"data");
    }

    #[test]
    /// H2 修复验证：域名/IPv6 目标的地址头编解码往返
    /// （旧版 encode 只接受 SocketAddr，域名目标在客户端被丢成 0.0.0.0）
    fn test_addr_header_domain_and_ipv6() {
        // 域名目标
        let mut out = Vec::new();
        encode_udp_addr_header_host("dns.example.com", 53, &mut out);
        let (host, port, payload) = parse_udp_addr_header(&out).unwrap();
        assert_eq!(host, "dns.example.com");
        assert_eq!(port, 53);
        assert!(payload.is_empty());

        // IPv6 目标（字符串形式进地址头）
        let mut out6 = Vec::new();
        encode_udp_addr_header_host("::1", 5353, &mut out6);
        let (host6, port6, _) = parse_udp_addr_header(&out6).unwrap();
        assert_eq!(host6, "::1");
        assert_eq!(port6, 5353);
    }

    #[test]
    /// M3 修复验证：过期重组状态被清理
    fn test_reassembler_cleanup_expired() {
        let header = mk_header("127.0.0.1", 9900);
        let payload = vec![0xABu8; 2000];
        let frames = split_udp_frames(&header, &payload);
        let mut reasm = UdpReassembler::new();
        // 只投第一片（模拟对端发一半崩溃），pending 里留下残缺状态
        reasm.push(&frames[0]);
        assert_eq!(reasm.pending.len(), 1);
        // 立即清理：未超时（30s），状态保留
        assert_eq!(reasm.cleanup_expired(), 0);
        assert_eq!(reasm.pending.len(), 1);
        // 人为把创建时间回拨 31s -> 再清理应移除
        let stale = std::time::Instant::now() - std::time::Duration::from_secs(31);
        for v in reasm.created_at.values_mut() {
            *v = stale;
        }
        assert_eq!(reasm.cleanup_expired(), 1);
        assert!(reasm.pending.is_empty());
        assert!(reasm.created_at.is_empty());
    }
}
