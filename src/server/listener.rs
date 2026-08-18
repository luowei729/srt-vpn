//! server/listener.rs — 多客户端监听循环
//!
//! 设计决策（Q20）：
//! - 服务器支持多客户端并发，单端口监听多个客户端
//! - 每客户端独立 SRT 连接 + 独立会话空间（互不干扰）
//! - 认证流程：streamid 静态令牌 → 挑战-应答 → 会话空间建立

use std::sync::Arc;

use crate::config::Config;
use crate::srt::connection::{SrtConfig, SrtConnection};
use crate::tunnel::multiplex::{MuxDecoder, MuxEncoder};
use crate::tunnel::{FrameType, FLAG_RELIABLE};

/// 接受连接循环（阻塞直到出错）
///
/// 每个客户端：
/// 1. accept 新的 SRT 连接
/// 2. 校验 streamid 静态令牌
/// 3. 下发 CHALLENGE（nonce）
/// 4. 校验 RESPONSE（双 HMAC + 时间窗）
/// 5. 启动客户端处理任务（隧道读写 + 转发）
pub async fn accept_loop(srt_cfg: &SrtConfig, app_cfg: &Config) -> Result<(), String> {
    let mut client_count = 0usize;
    loop {
        // 达到最大客户端数时等待（P1 简单：拒绝新连接）
        if client_count >= app_cfg.max_clients {
            tracing::warn!(max = app_cfg.max_clients, "已达最大客户端数，拒绝新连接");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        // 阻塞式 accept（每客户端独立 SRT 连接）
        let conn = match SrtConnection::accept(srt_cfg) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accept 失败");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }
        };

        // 检查客户端来源（日志）
        if let Some(sid) = conn.get_streamid() {
            tracing::trace!(streamid = %sid, "新客户端 streamid");
        }

        // 认证流程
        let passphrase = app_cfg.passphrase.clone();
        let conn_arc = Arc::new(conn);
        match authenticate(&conn_arc, &passphrase).await {
            Ok(()) => {
                client_count += 1;
                let m = crate::metrics::metrics();
                m.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                m.total_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::info!(clients = client_count, "客户端认证通过，建立会话");

                // 启动客户端处理任务（隧道读写 + 转发出口）
                let cfg = app_cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(conn_arc, &cfg).await {
                        tracing::warn!(error = %e, "客户端处理结束");
                    }
                    let m = crate::metrics::metrics();
                    m.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "客户端认证失败");
                let m = crate::metrics::metrics();
                m.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                conn_arc.close();
            }
        }
    }
}

/// 认证流程：
/// 1. streamid 静态令牌校验（第一道门）
/// 2. 下发 CHALLENGE（nonce）
/// 3. 校验 RESPONSE（双 HMAC + 30s 时间窗）
async fn authenticate(conn: &Arc<SrtConnection>, passphrase: &str) -> Result<(), String> {
    // 1. streamid 令牌校验
    let sid = conn.get_streamid().ok_or("客户端未提供 streamid")?;
    if !crate::auth::verify_token(&sid, passphrase) {
        return Err("streamid 静态令牌校验失败".to_string());
    }
    tracing::info!("streamid 静态令牌校验通过");

    // 2. 生成 nonce 并下发 CHALLENGE 帧
    let nonce = crate::auth::challenge::generate_nonce();
    let challenge_payload = format!("nonce={nonce}");
    let mux = MuxEncoder::new(true);
    let frame = mux.encode_frame(FrameType::Challenge, 0, 0, challenge_payload.as_bytes());
    // 2026-08-19：移除 TS 壳，直接作为 SRT 消息发送
    conn.send(frame).map_err(|e| format!("发送 CHALLENGE 失败: {e}"))?;
    tracing::debug!("CHALLENGE 已下发");

    // 3. 等待 RESPONSE（带超时 10s）
    // 2026-08-19：接收通道改为 tokio mpsc 后，直接用 async recv_async（无 spawn_blocking）
    // 这里用 tokio::time::timeout 实现 10s 超时
    let conn_for_wait = conn.clone();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        async move {
            // 异步批量接收（真正的 async 等待，不阻塞 worker）
            loop {
                match conn_for_wait.recv_async().await {
                    Ok(msg) => {
                        let mut mux_dec = MuxDecoder::new();
                        if let Some(f) = crate::tunnel::multiplex::decode_srt_message(&msg.data, &mut mux_dec) {
                            if f.ftype == FrameType::Response {
                                return Some(f.payload);
                            }
                            tracing::debug!(ftype = ?f.ftype, "等待 RESPONSE 期间收到其他帧");
                        }
                    }
                    Err(_e) => return None,
                }
            }
        },
    )
    .await
    .map_err(|e| format!("等待 RESPONSE 任务异常: {e}"))?;

    let payload = response.ok_or("等待客户端 RESPONSE 超时或连接断开")?;
    // 解析 payload：timestamp=<unix 秒>,resp=<hex hmac>
    let payload_str = String::from_utf8_lossy(&payload);
    let mut ts_val: Option<i64> = None;
    let mut resp_val: Option<String> = None;
    for part in payload_str.split(',') {
        if let Some(v) = part.strip_prefix("timestamp=") {
            ts_val = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("resp=") {
            resp_val = Some(v.to_string());
        }
    }
    let (ts, resp) = match (ts_val, resp_val) {
        (Some(t), Some(r)) => (t, r),
        _ => return Err("RESPONSE 格式无效".to_string()),
    };

    // 4. 校验应答（HMAC + 时间窗 30s）
    let ok = crate::auth::challenge::verify_response(passphrase, &nonce, ts, &resp)
        .map_err(|e| format!("校验 RESPONSE 失败: {e}"))?;
    if !ok {
        return Err("挑战-应答校验失败（时间窗或 HMAC 不匹配）".to_string());
    }
    tracing::info!("挑战-应答认证通过");
    Ok(())
}

/// 处理单个客户端的隧道读写 + 转发出口
async fn handle_client(conn: Arc<SrtConnection>, cfg: &Config) -> Result<(), String> {
    // 单层可靠模型：可靠传输交给 SRT 层
    // 复用层只做：分帧路由 + 会话管理 + 转发出口
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
    // 诊断：全局接收计数（断开时打印）
    let mut g_rx_total: u64 = 0;
    let mut g_rx_frames: u64 = 0;


    // 接收循环（异步批量读 SRT → 复用帧分发）
    // 2026-08-19：改用批量接收（recv_batch_async），一次处理多条消息，
    // 避免逐帧 spawn_blocking 的高频调度开销；SRT 消息直接承载隧道帧（无 TS 壳）。
    loop {
        let batch = match conn.recv_batch_async(512).await {
            Ok(b) => {
                g_rx_frames += b.len() as u64;
                b
            }
            Err(e) => {
                tracing::info!(error = %e, "客户端连接关闭");
                break;
            }
        };
        for msg in batch {
            let frame = match crate::tunnel::multiplex::decode_srt_message(&msg.data, &mut mux_dec) {
                Some(f) => f,
                None => {
                    tracing::warn!("收到无效隧道帧");
                    continue;
                }
            };

            // 用分发器处理 Data/Fin/Close/Open 帧
            match crate::tunnel::dispatch::dispatch_frame(&frame, &registry) {
                crate::tunnel::dispatch::DispatchAction::Routed => {
                    // 数据已路由到对应 forward 会话
                    g_rx_total += frame.payload.len() as u64;
                    tracing::trace!(session = frame.session_id, len = frame.payload.len(), "数据已路由到转发会话");
                }
                crate::tunnel::dispatch::DispatchAction::UnknownSession(sid) => {
                    tracing::warn!(session = sid, "数据帧无法路由（转发会话不存在）");
                }
                crate::tunnel::dispatch::DispatchAction::Fin(sid) => {
                    // 客户端 FIN（半关闭）：转发任务会从 recv 得到 None 触发半关闭
                    tracing::debug!(session = sid, "客户端 FIN（半关闭）");
                    registry.remove(sid);
                }
                crate::tunnel::dispatch::DispatchAction::Closed(sid) => {
                    tracing::info!(session = sid, "客户端关闭会话");
                    registry.remove(sid);
                }
                crate::tunnel::dispatch::DispatchAction::Open(sid, payload) => {
                    // 客户端请求打开会话 → 建立到目标的直连转发
                    tracing::info!(session = sid, "客户端请求打开会话");
                    // 先同步注册会话接收通道（保证后续 Data 帧能立即路由）
                    // 关键：Open 帧到达时立即注册，避免数据帧先到导致"会话不存在"
                    match registry.register_specific(sid) {
                        Some(rx) => {
                            let conn_c = conn.clone();
                            let mux_c = mux_enc_arc.clone();
                            let reg_c = registry.clone();
                            tracing::debug!(session = sid, "会话通道已注册，spawn 转发任务");
                            tokio::spawn(async move {
                                tracing::debug!(session = sid, "转发任务开始执行");
                                if let Err(e) = crate::server::forward::handle_open_with_rx(
                                    sid, &payload, rx, conn_c, mux_c, reg_c,
                                ).await {
                                    tracing::warn!(session = sid, error = %e, "转发会话处理结束");
                                }
                            });
                        }
                        None => {
                            tracing::warn!(session = sid, "会话 ID 已被占用，拒绝打开");
                            registry.remove(sid);
                        }
                    }
                }
                crate::tunnel::dispatch::DispatchAction::Other => {
                    // 其他帧：心跳/ACK/Challenge 等
                    match frame.ftype {
                        FrameType::Heartbeat => {
                            // 心跳：回发心跳帧（保持双向活跃）
                            let hb = mux_enc_arc.encode_heartbeat();
                            if let Err(e) = conn.send(hb) {
                                tracing::warn!(error = %e, "回发心跳失败");
                            }
                        }
                        FrameType::Challenge => {
                            tracing::debug!("收到 CHALLENGE（客户端角色才会收到，忽略）");
                        }
                        FrameType::Ack => {
                            tracing::trace!(session = frame.session_id, "收到 ACK");
                        }
                        _ => {
                            tracing::debug!(ftype = ?frame.ftype, "未处理帧类型");
                        }
                    }
                }
            }
        }
    }

    // 客户端断开：清理所有会话
    tracing::info!(frames = g_rx_frames, data_bytes = g_rx_total, "客户端断开，清理会话空间");
    Ok(())
}

/// 辅助：检查帧是否带可靠标志（供日志/统计）
#[allow(dead_code)]
fn is_reliable_frame(flags: u8) -> bool {
    flags & FLAG_RELIABLE != 0
}
