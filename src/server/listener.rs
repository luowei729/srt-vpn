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
use crate::tunnel::FrameType;

/// 接受连接循环（阻塞直到出错）
///
/// 每个客户端：
/// 1. accept 新的 SRT 连接
/// 2. 校验 streamid 静态令牌
/// 3. 下发 CHALLENGE（nonce）
/// 4. 校验 RESPONSE（双 HMAC + 时间窗）
/// 5. 启动客户端处理任务（隧道读写 + 转发）
///
/// 2026-08-19 M1 修复：accept + 认证整体 spawn 到独立任务。
/// 旧实现在 async 上下文直接调阻塞的 SrtConnection::accept（占死一个 tokio
/// worker 直到下一个客户端到来），且认证（300ms 握手 sleep + 最长 10s 超时）
/// 在 accept_loop 主循环内完成 -> 多客户端接入被完全串行化。
/// 现在名额检查改为原子计数快照，每连接独立 spawn 认证+处理，
/// 第 2 个客户端无需等第 1 个认证完成。
pub async fn accept_loop(srt_cfg: &SrtConfig, app_cfg: &Config) -> Result<(), String> {
    // 活跃客户端计数（原子）：主循环读取判断限流，任务结束时递减
    // 2026-08-19 审查修复（B1 max_clients 计数泄漏）：
    // 此前是普通局部变量只增不减，客户端断开后 max_clients 被离线客户端永久占满，
    // 服务器最终拒绝所有新连接。现改为 Arc<AtomicUsize>，客户端任务结束时 fetch_sub(1)。
    let client_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // 2026-08-19 M1 配套修复（accept 并行化端口冲突 bug）：
    // 旧模型每连接重建监听 socket（bind->listen->accept(1个)->close），
    // 并行化后多任务同时 bind 同一端口 -> "Another socket is already listening"
    // 无限报错（新加坡部署实测）。现监听 socket 建立一次常驻（SrtListener），
    // 各 accept 任务并发调 accept_one（srt_accept 线程安全）。
    let listener = {
        let cfg = srt_cfg.clone();
        tokio::task::spawn_blocking(move || SrtConnection::bind_listener(&cfg))
            .await
            .map_err(|e| format!("监听任务异常: {e}"))?
            .map_err(|e| format!("SRT 监听建立失败: {e}"))?
    };
    let listener = Arc::new(listener);

    loop {
        // 2026-08-19 M1 最终修正（吸取两版教训）：
        // - 第一版（串行全流程）：认证阻塞 accept，多客户端接入串行化
        // - 第二版（预 spawn 无限 accept 任务）：1500+ 任务同时阻塞在
        //   srt_accept 排队，名额瞬间被预占耗尽，主循环永远卡在
        //   "已达最大客户端数" -> 真实客户端永远进不来（新加坡部署实测）
        // - 本版（正确模型）：主循环串行 accept（一次一个，名额可控），
        //   accept 到连接后立即 spawn「认证+处理」任务（认证不再阻塞
        //   下一个 accept，多客户端并行接入的 M1 目标仍达成）
        // 达到最大客户端数时等待（此时挂起的 accept 任务为 0，名额语义精确）
        let cur = client_count.load(std::sync::atomic::Ordering::Relaxed);
        if cur >= app_cfg.max_clients {
            tracing::warn!(max = app_cfg.max_clients, active = cur, "已达最大客户端数，暂停接受新连接");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        // 名额预占（accept 期间占住 1 个，防并发超卖）
        client_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // 串行 accept（阻塞等下一个客户端；spawn_blocking 不占 tokio worker）
        let listener_c = listener.clone();
        let conn = match tokio::task::spawn_blocking(move || listener_c.accept_one()).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "accept 失败");
                client_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                // accept 失败退避（防异常时 CPU 空转）
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept 任务异常");
                client_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
        };

        // accept 到连接：spawn「认证 + 处理」任务（并行化，不阻塞下一个 accept）
        // 名额已预占，由任务结束/认证失败时释放
        let cfg_c = app_cfg.clone();
        let count_c = client_count.clone();
        tokio::spawn(async move {

            // 检查客户端来源（日志）
            if let Some(sid) = conn.get_streamid() {
                tracing::trace!(streamid = %sid, "新客户端 streamid");
            }

            let conn_arc = std::sync::Arc::new(conn);
            // 认证（含 S3 修复：窗口期数据帧缓存回放）
            match authenticate(&conn_arc, &cfg_c.passphrase.clone()).await {
                Ok(authed_frames) => {
                    let m = crate::metrics::metrics();
                    m.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    m.total_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(clients = count_c.load(std::sync::atomic::Ordering::Relaxed), "客户端认证通过，建立会话");

                    // 启动客户端处理任务（隧道读写 + 转发出口）
                    // 任务结束（正常/异常/断开）时释放客户端名额 + 递减连接指标
                    let cfg = cfg_c.clone();
                    let count = count_c.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(conn_arc, &cfg, authed_frames).await {
                            tracing::warn!(error = %e, "客户端处理结束");
                        }
                        // 释放 max_clients 名额（B1：防止计数只增不减）
                        count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        let m = crate::metrics::metrics();
                        m.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "客户端认证失败");
                    let m = crate::metrics::metrics();
                    m.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // close() 已幂等（S1 修复），Drop 再关一次无害
                    conn_arc.close();
                    count_c.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });
    }
}

/// 认证流程：
/// 1. streamid 静态令牌校验（第一道门）
/// 2. 下发 CHALLENGE（nonce）
/// 3. 校验 RESPONSE（双 HMAC + 30s 时间窗）
///
/// 返回认证期间到达的业务帧缓存（S3 修复：回放给 handle_client，不再丢弃）。
/// nonce 为连接内一次性下发（每连接仅一次 CHALLENGE/RESPONSE 交互），
/// 连接级隔离保证 nonce 不可跨连接重放（M2）。
async fn authenticate(
    conn: &Arc<SrtConnection>,
    passphrase: &str,
) -> Result<Vec<crate::tunnel::multiplex::Frame>, String> {
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
    // S3 修复（2026-08-19）：非 Response 帧（Open/Data 等客户端提前发来的业务帧）
    // 缓存起来认证通过后回放，不再丢弃（丢弃会导致请求黑洞+客户端会话泄漏）
    let conn_for_wait = conn.clone();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        async move {
            // 异步批量接收（真正的 async 等待，不阻塞 worker）
            // S3：非 Response 业务帧缓存到本地 Vec，认证完成后随 payload 一起返回
            let mut buffered: Vec<crate::tunnel::multiplex::Frame> = Vec::new();
            loop {
                match conn_for_wait.recv_async().await {
                    Ok(msg) => {
                        let mut mux_dec = MuxDecoder::new();
                        if let Some(f) = crate::tunnel::multiplex::decode_srt_message(&msg.data, &mut mux_dec) {
                            if f.ftype == FrameType::Response {
                                return Some((f.payload, buffered));
                            }
                            // S3：缓存窗口期业务帧（仅保留可回放类型，心跳等控制帧忽略）
                            if matches!(
                                f.ftype,
                                FrameType::Open | FrameType::Data | FrameType::Fin | FrameType::Close
                            ) {
                                tracing::debug!(ftype = ?f.ftype, "认证窗口期缓存业务帧（认证后回放）");
                                buffered.push(f);
                            }
                        }
                    }
                    Err(_e) => return None,
                }
            }
        },
    )
    .await
    .map_err(|_| "等待 RESPONSE 超时（10s）".to_string())?;

    let (payload, buffered_frames) = response.ok_or("等待客户端 RESPONSE 超时或连接断开")?;
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
    tracing::info!(buffered = buffered_frames.len(), "挑战-应答认证通过");
    Ok(buffered_frames)
}

/// 处理单个客户端的隧道读写 + 转发出口
///
/// buffered_frames：认证窗口期到达的业务帧（S3 修复：先回放再进入正常接收循环）
async fn handle_client(
    conn: Arc<SrtConnection>,
    cfg: &Config,
    buffered_frames: Vec<crate::tunnel::multiplex::Frame>,
) -> Result<(), String> {
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

    // 2026-08-19 审查修复（B4 主动心跳 + 死连接检测，服务端）：
    // 此前 server 只在"收到心跳帧"时被动回发，未主动定时发送、也无法发现
    // 长时间静默的死连接（客户端异常断网但不发 FIN 时连接永久占用）。
    // 现用 tokio::select! 把「接收批量」与「主动心跳定时器」合并：
    // - 心跳间隔内无任何帧到达 → 定时主动发一帧心跳（保活双向 NAT 映射）
    // - 连续多次发心跳后对端仍无任何数据 → 判定死连接，accumulated 心跳超时计数 + 断开
    // 收到任意帧都会重置心跳静默计数（有双向活动说明对端仍在）。
    let heartbeat_secs = cfg.heartbeat_secs.max(1);
    let heartbeat_dur = std::time::Duration::from_secs(heartbeat_secs);
    // 连续 N 个心跳周期对端无任何数据 → 判定死连接（N=3，容忍丢一帧心跳）
    const HEARTBEAT_DEAD_AFTER: u32 = 3;
    let mut heartbeat_dead_count: u32 = 0;
    // S3 修复：回放认证窗口期缓存的业务帧（Open/Data/Fin/Close）。
    // 这些帧是客户端在认证完成前已发出的请求（如 SOCKS5 首个 CONNECT），
    // 旧实现丢弃它们导致请求黑洞 + 客户端会话泄漏。
    if !buffered_frames.is_empty() {
        tracing::info!(count = buffered_frames.len(), "回放认证窗口期缓存的业务帧");
        for frame in &buffered_frames {
            dispatch_one_frame(frame, &conn, &mux_enc_arc, &registry);
        }
    }
    loop {
        // 接收 + 心跳定时：批量接收带超时（超时周期 = 心跳间隔）
        // 用 pin! 固定 sleep 以便 select 里可 reset（收到帧时重置心跳静默计数）
        let mut heartbeat_tick = std::pin::pin!(tokio::time::sleep(heartbeat_dur));

        tokio::select! {
            // 分支 1：批量接收 SRT 消息
            recv = conn.recv_batch_async(512) => {
                let batch = match recv {
                    Ok(b) => {
                        // 收到数据 → 对端活跃，重置心跳静默计数
                        heartbeat_dead_count = 0;
                        b
                    }
                    Err(e) => {
                        tracing::info!(error = %e, "客户端连接关闭");
                        break;
                    }
                };
                g_rx_frames += batch.len() as u64;
                for msg in batch {
                    let frame = match crate::tunnel::multiplex::decode_srt_message(&msg.data, &mut mux_dec) {
                        Some(f) => f,
                        None => {
                            tracing::warn!("收到无效隧道帧");
                            continue;
                        }
                    };
                    g_rx_total += frame.payload.len() as u64;
                    // S3 抽取：单帧分发（与认证回放共用同一路径，行为一致）
                    dispatch_one_frame(&frame, &conn, &mux_enc_arc, &registry);
                }
            }
            // 分支 2：心跳定时周期到 -- 主动发心跳，检测死连接
            _ = &mut heartbeat_tick => {
                // 连续若干周期对端无任何数据 -> 判定死连接，断开
                heartbeat_dead_count += 1;
                if heartbeat_dead_count >= HEARTBEAT_DEAD_AFTER {
                    tracing::warn!(dead_cycles = heartbeat_dead_count, secs = heartbeat_secs, "客户端心跳超时，判定死连接断开");
                    let m = crate::metrics::metrics();
                    m.heartbeat_timeouts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                // 其它情况：主动发心跳帧保活（对端 NAT/中间态保持）
                let hb = mux_enc_arc.encode_heartbeat();
                if let Err(e) = conn.send(hb) {
                    tracing::warn!(error = %e, "主动发送心跳失败");
                    break;
                }
                tracing::trace!(dead_count = heartbeat_dead_count, "主动发送心跳");
            }
        }
    }
    // 客户端断开：清理所有会话（S3 配套：close_all 让全部转发任务感知退出）
    let closed_sessions = registry.close_all();
    tracing::info!(frames = g_rx_frames, data_bytes = g_rx_total, closed_sessions = closed_sessions, "客户端断开，清理会话空间");
    Ok(())
}

/// 单帧分发（主循环与认证回放共用，S3 抽取）
///
/// 处理 Data/Fin/Close/Open 的路由与会话建立，以及心跳等控制帧回执。
/// 抽成独立函数的原因：认证窗口期缓存的帧回放必须与正常路径**完全一致**，
/// 避免两处维护同一套分发逻辑产生行为分叉。
fn dispatch_one_frame(
    frame: &crate::tunnel::multiplex::Frame,
    conn: &Arc<SrtConnection>,
    mux_enc_arc: &Arc<MuxEncoder>,
    registry: &crate::tunnel::dispatch::SessionRegistry,
) {
    // 用分发器处理 Data/Fin/Close/Open 帧
    match crate::tunnel::dispatch::dispatch_frame(frame, registry) {
        crate::tunnel::dispatch::DispatchAction::Routed => {
            // 数据已路由到对应 forward 会话
            tracing::trace!(session = frame.session_id, len = frame.payload.len(), "数据已路由到转发会话");
        }
        crate::tunnel::dispatch::DispatchAction::UnknownSession(sid) => {
            // 2026-08-20 修复（多线程上传带宽暴跌根因之二）：
            // 数据帧找不到会话 = 客户端还在向已死的会话灌数据（僵尸会话）。
            // 旧实现只打日志丢弃，客户端永远不知道会话已死，持续白灌数据
            // （实测故障时段 2039 帧/分钟被丢，隧道带宽被垃圾帧占满）。
            // 现回发 Rst 帧：客户端收到后立即停止发送并释放本地会话（加速收敛）。
            tracing::warn!(session = sid, "数据帧无法路由（转发会话不存在），回发 Rst 通知客户端清理");
            let rst = mux_enc_arc.encode_frame(FrameType::Rst, sid, 0, &[]);
            if let Err(e) = conn.send(rst) {
                tracing::debug!(session = sid, error = %e, "发送 Rst 失败（隧道可能已断开）");
            }
        }
        crate::tunnel::dispatch::DispatchAction::Fin(sid) => {
            // 客户端 FIN（半关闭）：事件已由 dispatch_frame 投递到会话通道，
            // 转发任务收到 SessionEvent::Fin 后自行处理半关闭（shutdown 目标写侧），
            // 剩余响应数据仍可路由回来（B2 半关闭语义，不再直接删会话）
            tracing::debug!(session = sid, "客户端 FIN（半关闭）");
        }
        crate::tunnel::dispatch::DispatchAction::Closed(sid) => {
            // 客户端 Close：事件已投递到会话通道，转发任务收到后清理退出；
            // 此处仅记录日志（不再直接 remove，避免与任务 Drop 双重移除）
            tracing::info!(session = sid, "客户端关闭会话");
        }
        // 2026-08-20：客户端 Rst（其本地会话异常终止），事件已投递，
        // 服务端转发任务收到 Close 事件后自行退出（对称清理）
        crate::tunnel::dispatch::DispatchAction::Rst(sid) => {
            tracing::info!(session = sid, "客户端 Rst（会话已死），转发任务清理");
        }
        crate::tunnel::dispatch::DispatchAction::Open(sid, payload) => {
            // 客户端请求打开会话 -> 建立到目标的直连转发
            tracing::info!(session = sid, "客户端请求打开会话");
            // 先同步注册会话接收通道（保证后续 Data 帧能立即路由）
            // 关键：Open 帧到达时立即注册，避免数据帧先到导致"会话不存在"
            match registry.register_specific(sid) {
                Some(rx) => {
                    let conn_c = conn.clone();
                    let mux_c = mux_enc_arc.clone();
                    let reg_c = registry.clone();
                    let reg_cleanup = registry.clone();
                    tracing::debug!(session = sid, "会话通道已注册，spawn 转发任务");
                    tokio::spawn(async move {
                        tracing::debug!(session = sid, "转发任务开始执行");
                        if let Err(e) = crate::server::forward::handle_open_with_rx(
                            sid, &payload, rx, conn_c, mux_c, reg_c,
                        ).await {
                            tracing::warn!(session = sid, error = %e, "转发会话处理结束");
                        }
                        // 转发任务结束：从注册表移除（会话生命周期收口）
                        reg_cleanup.remove(sid);
                    });
                }
                None => {
                    // 2026-08-19 H4 修复：ID 已被占用 = 客户端协议异常（复用了
                    // 已存在会话的 ID）。旧实现 registry.remove(sid) 会把
                    // **现有正常会话**踢掉（其任务 rx 收 None 退出），
                    // 恶意客户端可用伪造 sid 的 Open 帧踢掉任意会话。
                    // 正确行为：不动现有会话，直接拒绝本次 Open 并回 Close
                    // 帧让对端清理其错误会话。
                    tracing::warn!(session = sid, "会话 ID 已被占用，拒绝 Open（不影响现有会话）");
                    let reject = mux_enc_arc.encode_frame(FrameType::Close, sid, 0, &[]);
                    if let Err(e) = conn.send(reject) {
                        tracing::debug!(session = sid, error = %e, "发送 Open 拒绝 Close 帧失败");
                    }
                }
            }
        }
        crate::tunnel::dispatch::DispatchAction::Other => {
            // 其他帧：心跳/ACK/Challenge 等
            match frame.ftype {
                FrameType::Heartbeat => {
                    // 心跳 pong（M8 RTT 测量）：原样回发**对端的心跳载荷**，
                    // 保留对端时间戳，发起方收到后 now-ts 即得 RTT。
                    // （旧实现回发自己新生成的心跳，时间戳被覆盖无法测 RTT）
                    let pong = mux_enc_arc.encode_frame(FrameType::Heartbeat, 0, 0, &frame.payload);
                    if let Err(e) = conn.send(pong) {
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
