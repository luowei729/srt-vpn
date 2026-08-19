//! client/mod.rs — 客户端模块
//!
//! 设计决策（Q1/Q10）：
//! - P1 仅 SOCKS5 入口（用户名密码认证，多用户哈希存储，监听可配）
//! - P2 接入 TUN（tun2 crate，客户端跨平台）
//! - 客户端流程：SOCKS5 监听 → 建立 SRT 连接（streamid 令牌）→
//!   挑战-应答认证 → 隧道复用（会话映射）→ 服务器转发

pub mod http_proxy;
pub mod proxy;
pub mod socks5;

use std::sync::Arc;

use crate::config::Config;
use crate::srt::connection::{SrtConfig, SrtConnection};
use crate::tunnel::multiplex::MuxEncoder;

/// 客户端运行入口
pub async fn run(cfg: &Config, args: &crate::cli::Args) -> Result<(), String> {
    let server_addr = cfg.server.clone().ok_or("客户端配置缺少 server 字段")?;
    // 解析服务器地址（host:port，支持 IPv4 与域名；IPv6 由 srt 层暂不支持）
    let peer_addr = resolve_addr(&server_addr).await?;

    // 0. 启动指标服务（如果配置了端口）
    // 2026-08-19 审查修复（F1）：此前只有服务端启动了 metrics HTTP，
    // 客户端 metrics_port 配置被静默忽略。
    if let Some(port) = cfg.metrics_port {
        let m = crate::metrics::metrics();
        m.active_connections.store(0, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            if let Err(e) = crate::metrics::Metrics::serve_http(port).await {
                tracing::warn!(error = %e, "指标服务异常");
            }
        });
    }

    // 1. 构建 SRT 连接配置（客户端：连接模式 + streamid 令牌）
    // streamid 设计（决策 Q11）：
    // - 配置里的 streamid 是"资源名"部分（如 live/srtvpn）
    // - 必须附加 k= 令牌（HMAC-SHA256(passphrase) 派生），否则服务端认证失败
    // - 自动保证：无论配置是否带 k=，最终 streamid 都包含有效令牌
    let streamid = match cfg.streamid.as_deref() {
        Some(sid) if sid.contains("k=") => sid.to_string(), // 已带令牌，直接用
        Some(sid) => {
            // 配置了资源名但没令牌：在基础格式上附加令牌
            let token = crate::auth::derive_token(&cfg.passphrase);
            format!("{sid},k={token}")
        }
        None => crate::auth::build_streamid(&cfg.passphrase, "live/srtvpn"),
    };
    let srt_cfg = SrtConfig {
        peer_addr,
        passphrase: cfg.passphrase.clone(),
        pbkeylen: crate::config::crypto_to_pbkeylen(&cfg.crypto),
        streamid: Some(streamid),
        rcv_latency: 1000,
        reliable: true, // 客户端跟随服务端协商，默认可靠
        message_api: true,
        payload_size: 1316, // SRT 官方默认 payload（SRT_LIVE_DEF_PLSIZE=1316）
        is_server: false,
    };

    // 2. 重连循环：建立连接 → 起 SOCKS5 服务 + 接收循环 + 心跳 → 断开后按配置重试
    // 2026-08-19 审查修复（B3 整链自动重连）：
    // 此前 connect_with_retry 只在"初始建连失败"时重试；运行中 SRT 断开后 recv_loop
    // 退出、主流程返回错误、进程退出，违背设计决策 Q16"5s 心跳 + 客户端自动重连"。
    // 现把"建连 + SOCKS5 服务 + 接收循环 + 主动心跳"整体放入重连循环：
    // 任一环节（尤其运行中断线）触发重建整个隧道。
    let interval = cfg.reconnect.as_ref().map(|r| r.interval_secs).unwrap_or(5);
    let max_retries = cfg.reconnect.as_ref().map(|r| r.max_retries).unwrap_or(10);
    let mut attempt = 0u64;
    let mut first_connect = true;

    // SOCKS5 监听地址与凭据（每次重连复用同一监听端口）
    let socks5_cfg = cfg.socks5.clone().unwrap_or_default();
    let listen_addr = args
        .socks5_listen
        .clone()
        .unwrap_or(socks5_cfg.listen.clone());

    loop {
        let conn = if first_connect {
            // 首次建连：调用 connect_with_retry（内部会按 reconnect 配置重试直到成功或达上限）
            first_connect = false;
            connect_with_retry(&srt_cfg, cfg).await?
        } else {
            // 断线重连：按 reconnect 配置重试上限
            attempt += 1;
            if max_retries >= 0 && attempt > max_retries as u64 {
                return Err(format!("SRT 连接失败（已达最大重试 {max_retries} 次）"));
            }
            tracing::warn!(attempt, interval, "隧道断开，准备重连");
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            match connect_once(&srt_cfg).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "重连 SRT 失败");
                    continue;
                }
            }
        };

        // S4 修复（2026-08-19）：连接成功进入服务态后清零重连计数。
        // 旧实现 attempt 是"累计断线次数"，长期运行的客户端累计达 max_retries
        // 后直接退出进程（瞬时抖动 10 次也不该退），违背 Q16 自动重连意图。
        // 语义改为"连续失败次数"：成功即清零。
        attempt = 0;
        tracing::info!("SRT 连接建立成功");
        let conn = Arc::new(conn);

        // 重建隧道组件（每次重连都是全新连接，编码器/注册表一并重建）
        let mux_enc = Arc::new(MuxEncoder::new(true));
        let registry = crate::tunnel::dispatch::SessionRegistry::new();
        let passphrase = cfg.passphrase.clone();

        // 注册指标连接数（客户端侧也统计活跃连接）
        let m = crate::metrics::metrics();
        m.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        m.total_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // 启动隧道接收循环（SRT 收 → 分发到会话）
        // 断开信号：recv_loop 退出时置位 → serve 停止 accept → 重连循环接管（B3）
        let (tunnel_closed_tx, tunnel_closed_rx) = tokio::sync::watch::channel(false);
        let recv_conn = conn.clone();
        let recv_mux = mux_enc.clone();
        let recv_reg = registry.clone();
        let recv_task = tokio::spawn(recv_loop(recv_conn, recv_mux, passphrase, recv_reg, tunnel_closed_tx));

        // 启动主动心跳定时器（B4：按 heartbeat_secs 周期主动发心跳帧保活）
        let hb_conn = conn.clone();
        let hb_mux = mux_enc.clone();
        let heartbeat_secs = cfg.heartbeat_secs.max(1);
        let hb_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(heartbeat_secs)).await;
                let hb = hb_mux.encode_heartbeat();
                if let Err(e) = hb_conn.send(hb) {
                    tracing::warn!(error = %e, "心跳发送失败");
                    break; // 连接不可用，退出心跳任务（由重连循环重建）
                }
            }
        });

        // 启动 SOCKS5 服务；运行中断开（serve 返回 Err）或监听失败 -> 按错误类型分流
        // S2 修复（2026-08-19）：监听失败（"listen:" 前缀）= 致命配置错误，
        // 重连一万次也解决不了端口被占 -> 直接退出进程让运维感知；
        // 其余 Err（隧道断开/accept 失败）-> 走重连循环。
        let serve_result = socks5::serve(&listen_addr, conn.clone(), mux_enc, registry, socks5_cfg.clone(), tunnel_closed_rx).await;
        // 心跳任务收尾（连接已失效，abort 防泄漏）
        hb_task.abort();
        // 释放连接指标
        m.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        // S2：recv_task 不再无条件 await（旧实现监听失败时 recv_loop 不会退出，
        // await 永久挂起卡死客户端）。abort 让其随连接失效终止；
        // 断线场景下 recv_loop 本就即将退出，abort 无副作用。
        recv_task.abort();

        match serve_result {
            Ok(()) => {
                // SOCKS5 监听正常退出（理论上不会发生，防御处理）
                return Ok(());
            }
            Err(e) => {
                if e.starts_with("listen:") {
                    // S2：监听失败 = 致命错误，直接退出（重连无意义）
                    return Err(e);
                }
                // 运行中断开/accept 失败 -> 走重连（B3 整链自动重连）
                tracing::warn!(error = %e, "SOCKS5 服务退出，进入重连");
                continue;
            }
        }
    }
}

/// 建立单次 SRT 连接（重连循环与初始建连共用）
async fn connect_once(srt_cfg: &SrtConfig) -> Result<SrtConnection, String> {
    // SRT 连接建立是同步阻塞（epoll 等待），用 spawn_blocking 避免阻塞 tokio worker
    // 注意：SrtConfig 是 Clone，必须克隆进闭包（spawn_blocking 要求 'static）
    let cfg = srt_cfg.clone();
    tokio::task::spawn_blocking(move || SrtConnection::connect(&cfg))
        .await
        .map_err(|e| format!("连接任务异常: {e}"))?
        .map_err(|e| format!("SRT 连接失败: {e}"))
}

/// 隧道接收循环：SRT 消息 → 复用帧分发
///
/// 职责（P1）：
/// - 处理 Challenge 帧：生成 RESPONSE（双 HMAC 挑战-应答认证）
/// - 处理 Heartbeat 帧：回发心跳（保活）
/// - 处理 Data 帧：路由到对应会话（dispatch_frame）
///
/// 性能优化（2026-08-19）：
/// - 移除 TS 伪装层，SRT 消息直接承载隧道帧
/// - 改用批量接收（recv_batch_async），一次处理多条消息，
///   避免逐帧 spawn_blocking 的高频调度开销
async fn recv_loop(
    conn: Arc<SrtConnection>,
    mux_enc_local: Arc<MuxEncoder>,
    passphrase: String,
    registry: crate::tunnel::dispatch::SessionRegistry,
    tunnel_closed_tx: tokio::sync::watch::Sender<bool>,
) {
    // 任务退出（隧道断开/异常）时置位断开信号，通知 SOCKS5 serve 停止 accept，
    // 让重连循环接管（B3 重连缺陷修复）。
    let result = run_recv_inner(conn, mux_enc_local, passphrase, registry).await;
    tracing::info!("隧道接收循环退出，通知 SOCKS5 服务停止");
    let _ = tunnel_closed_tx.send(true);
    result
}

/// recv_loop 的实际处理体（分离信号通知，便于退出时统一置位）
async fn run_recv_inner(
    conn: Arc<SrtConnection>,
    mux_enc_local: Arc<MuxEncoder>,
    passphrase: String,
    registry: crate::tunnel::dispatch::SessionRegistry,
) {
    let mut mux_dec = crate::tunnel::multiplex::MuxDecoder::new();
    loop {
        // 批量接收：一次拿最多 512 条消息（减少 spawn_blocking 调度次数）
        match conn.recv_batch_async(512).await {
            Ok(batch) => {
                for msg in batch {
                    // SRT 消息 → 复用层帧（无 TS 壳，直接解析帧头）
                    if let Some(frame) =
                        crate::tunnel::multiplex::decode_srt_message(&msg.data, &mut mux_dec)
                    {
                        // 先用分发器处理 Data/Fin/Close 帧
                        match crate::tunnel::dispatch::dispatch_frame(&frame, &registry) {
                            crate::tunnel::dispatch::DispatchAction::Routed => {
                                // 数据已路由到会话
                                tracing::trace!(session = frame.session_id, len = frame.payload.len(), "数据已路由到会话");
                            }
                            crate::tunnel::dispatch::DispatchAction::UnknownSession(sid) => {
                                tracing::warn!(session = sid, "数据帧无法路由（会话不存在）");
                            }
                            crate::tunnel::dispatch::DispatchAction::Fin(sid) => {
                                // 对端 FIN（半关闭）：事件已投递到会话通道，
                                // 转发任务收到 SessionEvent::Fin 后处理半关闭（shutdown 本地写侧）
                                tracing::debug!(session = sid, "对端 FIN（半关闭）");
                            }
                            crate::tunnel::dispatch::DispatchAction::Closed(sid) => {
                                // 对端 Close：事件已投递到会话通道，转发任务清理退出
                                tracing::debug!(session = sid, "对端关闭会话");
                            }
                            crate::tunnel::dispatch::DispatchAction::Open(_sid, _payload) => {
                                tracing::warn!("客户端收到意外的 Open 帧");
                            }
                            crate::tunnel::dispatch::DispatchAction::Other => {
                                match frame.ftype {
                                    crate::tunnel::FrameType::Challenge => {
                                        handle_challenge(&conn, &mux_enc_local, &frame, &passphrase);
                                    }
                                    crate::tunnel::FrameType::Heartbeat => {
                                        // M8 RTT 测量（2026-08-19）：对端回发的心跳载荷
                                        // 带的是**本端**此前发出的时间戳（pong 语义），
                                        // now - ts 即 RTT；若时间戳异常（时钟跳变/非本端
                                        // 发起），视为对端主动心跳，回发 pong（保留对端
                                        // 时间戳供对端测 RTT）。
                                        let ts = crate::tunnel::multiplex::heartbeat_timestamp(&frame.payload);
                                        let now_ms = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .map(|d| d.as_millis() as i64)
                                            .unwrap_or(0);
                                        let mut is_pong = false;
                                        if let Some(ts) = ts {
                                            let rtt = now_ms - ts;
                                            // RTT 合理性过滤：0~60s 内视为 pong（防时钟跳变误报）
                                            if (0..60_000).contains(&rtt) {
                                                tracing::debug!(rtt_ms = rtt, "心跳 pong（RTT）");
                                                let m = crate::metrics::metrics();
                                                m.last_rtt_ms.store(rtt.max(0) as u64, std::sync::atomic::Ordering::Relaxed);
                                                is_pong = true;
                                            }
                                        }
                                        if !is_pong {
                                            // 对端主动心跳：原样回发载荷（pong，保留对端时间戳）
                                            let pong = mux_enc_local.encode_frame(
                                                crate::tunnel::FrameType::Heartbeat,
                                                0,
                                                0,
                                                &frame.payload,
                                            );
                                            if let Err(e) = conn.send(pong) {
                                                tracing::warn!(error = %e, "回发心跳失败");
                                            }
                                        }
                                    }
                                    crate::tunnel::FrameType::Ack => {
                                        tracing::trace!(session = frame.session_id, "收到 ACK");
                                    }
                                    _ => {
                                        tracing::debug!(ftype = ?frame.ftype, "收到控制帧");
                                    }
                                }
                            }
                        }
                    } else {
                        tracing::warn!("收到无效隧道帧");
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "SRT 连接断开");
                break;
            }
        }
    }
    // S3 配套修复（2026-08-19）：隧道断开时清空会话注册表（close_all drop 全部
    // 通道 Sender），让所有本地转发任务 recv_event() 得到 None 自然退出。
    // 旧实现只退出接收循环，转发任务永久挂在 recv_event 上（任务+会话 ID 泄漏）。
    let closed = registry.close_all();
    if closed > 0 {
        tracing::info!(sessions = closed, "隧道断开，关闭全部本地会话任务");
    }
}

/// 处理挑战-应答：解析服务器下发的 nonce，生成并发送 RESPONSE
///
/// 服务器 CHALLENGE 载荷格式：`nonce=<hex>`
/// 客户端 RESPONSE 载荷格式：`timestamp=<unix秒>,resp=<hex hmac>`
fn handle_challenge(
    conn: &SrtConnection,
    mux_enc: &MuxEncoder,
    frame: &crate::tunnel::multiplex::Frame,
    passphrase: &str,
) {
    // 1. 解析 nonce（载荷格式：nonce=<hex>）
    let payload_str = String::from_utf8_lossy(&frame.payload);
    let nonce = payload_str.strip_prefix("nonce=").map(|s| s.to_string());
    let nonce = match nonce {
        Some(n) if !n.is_empty() => n,
        _ => {
            tracing::warn!(payload = %payload_str, "CHALLENGE 载荷格式无效");
            return;
        }
    };

    // 2. 生成应答（时间戳 + HMAC-SHA256(passphrase, nonce + 时间戳)）
    let timestamp = crate::auth::challenge::current_timestamp();
    let resp = crate::auth::challenge::compute_response(passphrase, &nonce, timestamp);

    // 3. 构造 RESPONSE 帧并直接发送（无 TS 壳，直接作为 SRT 消息）
    let resp_payload = format!("timestamp={timestamp},resp={resp}");
    let frame = mux_enc.encode_frame(
        crate::tunnel::FrameType::Response,
        0,
        0,
        resp_payload.as_bytes(),
    );
    if let Err(e) = conn.send(frame) {
        tracing::warn!(error = %e, "发送 RESPONSE 失败");
    } else {
        tracing::info!("挑战-应答 RESPONSE 已发送");
    }
}

/// 带重连的 SRT 连接（设计决策：5s 心跳 + 客户端自动重连）
///
/// 2026-08-19 审查修复（B3）：
/// - SRT 连接建立是同步阻塞（内部 epoll 等待最多 5s + 200ms 就绪 sleep），
///   改走 spawn_blocking（connect_once），避免阻塞 tokio worker 线程。
async fn connect_with_retry(cfg: &SrtConfig, app_cfg: &Config) -> Result<SrtConnection, String> {
    let interval = app_cfg.reconnect.as_ref().map(|r| r.interval_secs).unwrap_or(5);
    let max_retries = app_cfg.reconnect.as_ref().map(|r| r.max_retries).unwrap_or(10);
    let mut attempt = 0u64;
    loop {
        match connect_once(cfg).await {
            Ok(conn) => {
                tracing::info!(attempt, "SRT 连接建立成功");
                return Ok(conn);
            }
            Err(e) => {
                attempt += 1;
                if max_retries >= 0 && attempt > max_retries as u64 {
                    return Err(format!("SRT 连接失败（已达最大重试 {max_retries} 次）: {e}"));
                }
                tracing::warn!(attempt, interval, error = %e, "SRT 连接失败，准备重连");
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        }
    }
}

/// 解析 host:port 地址（支持 IPv4 字面量与域名，返回 SocketAddr）
///
/// 2026-08-19 passwall 对接增强：passwall 节点地址常填域名（vpn.example.com:9000），
/// 原 parse_addr 用 SocketAddr::parse 只接受 IP 字面量（域名报"地址格式无效"）。
/// 现拆成两步：
///   1. 先按 IP 字面量解析（127.0.0.1:9000 -> 直接成功，保持原有行为）
///   2. 失败则按域名用 tokio lookup_host 解析（取第一个解析结果）
/// 注意：仅解析出 SocketAddr 传给 SRT 层，不影响 srt 层只支持 IPv4 的限制
pub async fn resolve_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    // 1. IP 字面量优先（原 parse_addr 行为，零开销）
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return Ok(sa);
    }

    // 2. 域名解析（如 vpn.example.com:9000）
    // tokio 内部走 getaddrinfo，支持 A/AAAA 记录
    let mut addrs = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| format!("域名解析失败: {addr}: {e}"))?;
    // 优先取 IPv4（SRT 层只支持 IPv4，见 sockaddr_from）
    let first_v4 = addrs.find(|a| a.is_ipv4());
    first_v4.ok_or_else(|| format!("地址格式无效或无可用的 IPv4 解析结果: {addr}（应为 host:port）"))
}
// L 级清理（2026-08-19）：crypto_to_pbkeylen 重复实现移除，统一用 config::crypto_to_pbkeylen
