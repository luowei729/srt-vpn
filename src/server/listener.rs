//! server/listener.rs — 多客户端监听循环（2026-08-20 重构版）
//!
//! 设计决策（Q20）：
//! - 服务器支持多客户端并发，单端口监听多个客户端
//! - 每客户端独立 QUIC 连接 + 独立会话空间（互不干扰）
//! - 认证：QuicListener 握手内完成（SRT 特征 AUTH，srt_shell/auth.rs）
//!   （旧双 HMAC 挑战-应答已按重构共识移除）
//!
//! 线程模型：
//! - 单 QuicListener（一个 UDP socket）接收所有客户端握手
//! - 每个 accept 出的客户端一个 QuicConnection（共享监听 socket + peer 隔离）
//! - 每客户端独立 spawn 处理任务（隧道读写 + 转发出口）

use std::sync::Arc;

use crate::config::Config;
use crate::quic::connection::QuicConnection;
use crate::quic::listener::QuicListener;
use crate::tunnel::multiplex::{MuxDecoder, MuxEncoder};

/// 接受连接循环（阻塞直到出错）
///
/// 每个客户端：accept（QuicListener 内建 SRT 特征握手认证）→ spawn 处理任务。
/// 多客户端并行接入：主循环非阻塞 accept（名额可控），accept 到后立即
/// spawn 处理任务（并行目标不变）。
pub async fn accept_loop(
    listen_addr: std::net::SocketAddr,
    secret: [u8; 16],
    heartbeat_secs: u64,
    app_cfg: &Config,
) -> Result<(), String> {
    // 活跃客户端计数（原子）：主循环读取判断限流，任务结束时递减
    //（B1 修复保真：防 max_clients 计数泄漏）
    let client_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // 建立监听器：单 UDP socket 常驻（M1 教训：监听 socket 是全局唯一资源，
    // 每连接重建必端口冲突）
    let listener = Arc::new(
        QuicListener::bind(quic_addr(listen_addr), secret, heartbeat_secs)
            .map_err(|e| format!("QUIC 监听建立失败: {e}"))?,
    );
    tracing::info!(listen = %listen_addr, "监听已建立，等待客户端...");

    loop {
        // 名额控制：max_clients 内才 accept（原子计数快照）
        let cur = client_count.load(std::sync::atomic::Ordering::Relaxed);
        if cur >= app_cfg.max_clients {
            tracing::warn!(max = app_cfg.max_clients, active = cur, "已达最大客户端数，暂停接受新连接");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }
        // 名额预占（accept 期间占位，防并发超卖）
        client_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // accept：QuicListener::accept 非阻塞扫描握手；未到包返回 None，
        // 先复制要用的数据（避免借用逃逸到闭包/任务）
        let l_c = listener.clone();
        let max_guard = app_cfg.max_clients + 8;
        let conn_opt = tokio::task::spawn_blocking(move || {
            // 非阻塞 accept：轮询少量次数（每次 50ms，至多 ~1s）避免忙等
            for _ in 0..20 {
                match l_c.accept(max_guard) {
                    Ok(Some(c)) => return Some(c),
                    Ok(None) => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    }
                    Err(_e) => return None,
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        if conn_opt.is_none() {
            // accept 无新客户端（超时）：释放名额继续
            client_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }
        let conn = conn_opt.unwrap();

        // accept 到连接：spawn 处理任务（名额已预占，任务结束释放）
        let cfg_c = app_cfg.clone();
        let count_c = client_count.clone();
        tokio::spawn(async move {
            let m = crate::metrics::metrics();
            m.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            m.total_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(clients = count_c.load(std::sync::atomic::Ordering::Relaxed), "客户端接入，建立会话");

            // 处理客户端（隧道读写 + 转发出口）；无论成败释放名额
            if let Err(e) = handle_client(conn, &cfg_c).await {
                tracing::warn!(error = %e, "客户端处理结束");
            }
            count_c.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            let m2 = crate::metrics::metrics();
            m2.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}

/// 把 host:port 字符串解析成 SocketAddr（容忍 IPv4 + 域名？服务端 listen 必是 IP）
fn quic_addr(sa: std::net::SocketAddr) -> std::net::SocketAddr {
    sa
}

/// 处理单个客户端的隧道读写 + 转发出口
///
/// 数据路径：QuicConnection 主数据流事件（RecvEvent::Data）→ Mux 帧 → 分发。
/// 心跳由内核层（srt_shell/ack.rs + QuicConnection 超时检测）承担。
async fn handle_client(
    conn: Arc<QuicConnection>,
    cfg: &Config,
) -> Result<(), String> {
    let reliable = match cfg.udp_mode {
        crate::cli::UdpMode::Reliable => true,
        crate::cli::UdpMode::BestEffort => false,
    };

    // 每客户端独立会话空间（决策 Q20）：SessionRegistry 按客户端隔离
    let registry = crate::tunnel::dispatch::SessionRegistry::new();
    let mut mux_dec = MuxDecoder::new();
    let mux_enc = MuxEncoder::new(reliable);
    let mux_enc_arc = Arc::new(mux_enc);

    tracing::info!("客户端隧道处理开始");
    let mut g_rx_total: u64 = 0;
    let mut g_rx_frames: u64 = 0;

    // 取该客户端连接的事件流（单消费者；连接为每个客户端独立创建）
    let mut rx = match conn.take_events() {
        Some(rx) => rx,
        None => {
            tracing::warn!("连接事件流已被消费，客户端处理退出");
            registry.close_all();
            return Ok(());
        }
    };

    loop {
        // 从 QUIC 事件流阻塞读一条（等待新数据；连接断开/销毁时通道关闭得 None）
        // QUIC 内部有超时断线检测（heartbeat_secs），此处无需额外超时
        // ——若对端静默，QuicConnection::recv_loop 置 closed，最终通道关闭。
        let ev = match rx.recv().await {
            Some(ev) => ev,
            None => {
                tracing::info!("QUIC 事件流关闭，客户端断开");
                break;
            }
        };
        // 批量取（非阻塞）减少 handle 切换
        let mut batch = vec![ev];
        while let Ok(ev) = rx.try_recv() {
            batch.push(ev);
        }
        for ev in batch {
            match ev {
                crate::quic::connection::RecvEvent::Data { data, .. } => {
                    // 2026-08-20 性能优化：decode_frame_view 避免每帧 Vec alloc
                    // （上传 18000 包/s × 1301B = 23MB/s 分配率是上传瓶颈之一）
                    match crate::tunnel::multiplex::decode_srt_message_view(&data, &mut mux_dec) {
                        Some((ftype, sid, seq, flags, payload)) => {
                            g_rx_frames += 1;
                            g_rx_total += payload.len() as u64;
                            dispatch_frame_view(
                                ftype, sid, seq, flags, payload,
                                &conn, &mux_enc_arc, &registry,
                            );
                        }
                        None => { tracing::warn!("收到无效隧道帧"); }
                    }
                }
                crate::quic::connection::RecvEvent::Fin { stream_id } => {
                    tracing::debug!(stream = stream_id, "主数据流 FIN");
                }
                crate::quic::connection::RecvEvent::Reset { stream_id } => {
                    tracing::warn!(stream = stream_id, "主数据流被重置");
                    break;
                }
                crate::quic::connection::RecvEvent::Control(_payload) => {
                    tracing::trace!("收到连接控制消息");
                }
            }
        }
    }

    // 客户端断开：清理所有会话（S3 配套）
    let closed_sessions = registry.close_all();
    tracing::info!(frames = g_rx_frames, data_bytes = g_rx_total, closed_sessions = closed_sessions, "客户端断开，清理会话空间");
    Ok(())
}

/// 单帧分发（会话路由 + Open 建立转发）
///
/// 2026-08-20 重构：conn 为 QuicConnection（发送用 send_async/send 兼容 API）。
#[allow(dead_code)]
fn dispatch_one_frame(
    frame: &crate::tunnel::multiplex::Frame,
    conn: &Arc<QuicConnection>,
    mux_enc_arc: &Arc<MuxEncoder>,
    registry: &crate::tunnel::dispatch::SessionRegistry,
) {
    // 兼容旧接口（保留用于测试/其他调用方）
    dispatch_frame_view(
        frame.ftype, frame.session_id, frame.seq, frame.flags, &frame.payload,
        conn, mux_enc_arc, registry,
    )
}

/// view 版分发（不复制 payload；Data 路由时一次性 alloc Vec）
///
/// 每帧省一次中间 Vec alloc + dispatch_frame 内 payload.clone() 二次分配。
/// Data 帧路由到 SessionEvent::Data(Vec) 仍需一次 alloc（channel 要 owned，
/// 无法避免），但 Open 帧的 payload 只在 Open 分支 alloc（传到 spawn task）。
fn dispatch_frame_view(
    ftype: crate::tunnel::FrameType,
    sid: u16,
    _seq: u32,
    _flags: u8,
    payload: &[u8],
    conn: &Arc<QuicConnection>,
    mux_enc_arc: &Arc<MuxEncoder>,
    registry: &crate::tunnel::dispatch::SessionRegistry,
) {
    use crate::tunnel::dispatch::DispatchAction;
    use crate::tunnel::FrameType;
    match crate::tunnel::dispatch::dispatch_frame_view(ftype, sid, payload, registry) {
        DispatchAction::Routed => {
            tracing::trace!(session = sid, len = payload.len(), "数据已路由到转发会话");
        }
        DispatchAction::UnknownSession(sid) => {
            tracing::warn!(session = sid, "数据帧无法路由（转发会话不存在），回发 Rst");
            let rst = mux_enc_arc.encode_frame(FrameType::Rst, sid, 0, &[]);
            if let Err(e) = conn.send(rst) {
                tracing::debug!(session = sid, error = %e, "发送 Rst 失败");
            }
        }
        DispatchAction::Fin(sid) => {
            tracing::debug!(session = sid, "客户端 FIN（半关闭）");
        }
        DispatchAction::Closed(sid) => {
            tracing::info!(session = sid, "客户端关闭会话");
        }
        DispatchAction::Rst(sid) => {
            tracing::info!(session = sid, "客户端 Rst（会话已死），转发任务清理");
        }
        DispatchAction::Open(sid, _) => {
            // Open 帧：用外层 view 的 payload（dispatch_frame_view 不复制）
            tracing::info!(session = sid, "客户端请求打开会话");
            // Open 帧的 payload 需要跨 spawn 边界 owned（一次性 alloc）
            let payload_owned = payload.to_vec();
            if registry.has(sid) {
                tracing::debug!(session = sid, "会话 ID 复用：先移除旧注册再接受新 Open");
                registry.remove(sid);
            }
            match registry.register_specific(sid) {
                Some(rx) => {
                    let conn_c = conn.clone();
                    let mux_c = mux_enc_arc.clone();
                    let reg_c = registry.clone();
                    let reg_cleanup = registry.clone();
                    tokio::spawn(async move {
                        if let Err(e) = crate::server::forward::handle_open_with_rx(
                            sid, &payload_owned, rx, conn_c, mux_c, reg_c,
                        ).await {
                            tracing::warn!(session = sid, error = %e, "转发会话处理结束");
                        }
                        reg_cleanup.remove(sid);
                    });
                }
                None => {
                    tracing::warn!(session = sid, "会话 ID 已被占用，拒绝 Open");
                    let reject = mux_enc_arc.encode_frame(FrameType::Close, sid, 0, &[]);
                    let _ = conn.send(reject);
                }
            }
        }
        DispatchAction::Other => {
            tracing::debug!(ftype = ?ftype, "未处理控制帧（心跳/ACK 由内核承担）");
        }
    }
}