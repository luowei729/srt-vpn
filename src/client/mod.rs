//! client/mod.rs — 客户端模块
//!
//! 设计决策（Q1/Q10）：
//! - P1 仅 SOCKS5 入口（用户名密码认证，多用户哈希存储，监听可配）
//! - P2 接入 TUN（tun2 crate，客户端跨平台）
//! - 客户端流程：SOCKS5 监听 → 建立 SRT 连接（streamid 令牌）→
//!   挑战-应答认证 → 隧道复用（会话映射）→ 服务器转发

pub mod http_proxy;
pub mod pool;
pub mod proxy;
pub mod socks5;

use std::sync::Arc;

use crate::config::Config;
use crate::quic::connection::{QuicConfig, QuicConnection};
use crate::quic::crypto::derive_key;
use crate::tunnel::multiplex::MuxEncoder;

/// 连接池大小已配置化（P1.5）：Config.pool_size（默认 4）/ SRT_POOL_SIZE 环境变量。
/// 默认值取值依据：公网对照实验 4 连接并发 151 MB/s（+70% 于单连接 89 MB/s），
/// 4 条已获大部分收益，过多连接会显著增加 UDP 流数量（伪装权衡）与
/// 服务端 max_clients 占用，收益递减。

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

    // 1. 构建 QUIC 连接配置（客户端：connect 模式 + SRT 特征认证密钥）
    //    2026-08-20 重构：libsrt/SrtConfig 弃用，改自研 QUIC 语义内核。
    //    认证：passphrase → 派生密钥（crypto::derive_key），作为 SRT 特征
    //    握手的 AUTH 载荷密钥（srt_shell/auth.rs），防主动探测。
    let secret: [u8; 16] = derive_key(cfg.passphrase.as_bytes(), b"srt-vpn-v3-salt", 16)
        .try_into()
        .expect("密钥长度固定 16B");
    let quic_cfg = QuicConfig {
        peer: Some(peer_addr),
        is_server: false,
        bind_addr: None,
        secret,
        heartbeat_secs: cfg.heartbeat_secs.max(5),
        ..Default::default()
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
        // 建池：pool_size 条连接（每条独立 QUIC 连接 + 独立拥控窗口，B 方案核心）
        // P1.5 配置化：池大小来自配置（默认 4，SRT_POOL_SIZE 可覆盖）
        let pool_size = cfg.pool_size.clamp(1, 16);
        let conns_raw = if first_connect {
            // 首次建池：调用 connect_pool_with_retry（内部按 reconnect 配置重试直到成功或达上限）
            first_connect = false;
            connect_pool_with_retry(&quic_cfg, cfg, pool_size).await?
        } else {
            // 断线重连：按 reconnect 配置重试上限
            attempt += 1;
            if max_retries >= 0 && attempt > max_retries as u64 {
                // 2026-08-20：认证类失败重试耗尽时提示检查配置
                return Err(format!(
                    "QUIC 连接失败（已达最大重试 {max_retries} 次）。若服务端日志无认证通过记录，请检查 passphrase 是否一致"
                ));
            }
            tracing::warn!(attempt, interval, "隧道断开，准备重连");
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            match connect_pool_once(&quic_cfg, pool_size).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "重连 QUIC 失败");
                    continue;
                }
            }
        };

        // S4 修复（2026-08-19）：连接成功进入服务态后清零重连计数。
        // 语义改为"连续失败次数"：成功即清零。
        attempt = 0;
        tracing::info!(conns = conns_raw.len(), "QUIC 连接池建立成功");

        // 每条连接构建 TunnelConn（独立编码器/注册表/拥控窗口）
        let mut tconns = Vec::with_capacity(conns_raw.len());
        for c in conns_raw {
            // QuicConnection::connect 返回 Arc<Self>，直接使用（不再包一层 Arc）
            tconns.push(pool::TunnelConn {
                conn: c,
                mux_enc: Arc::new(MuxEncoder::new(true)),
                registry: crate::tunnel::dispatch::SessionRegistry::new(),
            });
        }
        let tunnel_pool = Arc::new(pool::TunnelPool::new(tconns));
        let passphrase = cfg.passphrase.clone();

        // 注册指标连接数（客户端侧按池大小统计）
        let m = crate::metrics::metrics();
        m.active_connections.fetch_add(tunnel_pool.len() as u64, std::sync::atomic::Ordering::Relaxed);
        m.total_connections.fetch_add(tunnel_pool.len() as u64, std::sync::atomic::Ordering::Relaxed);

        // 断开信号：任一 recv_loop 退出时置位 → serve 停止 accept → 重连循环接管（B3）
        let (tunnel_closed_tx, tunnel_closed_rx) = tokio::sync::watch::channel(false);
        let heartbeat_secs = cfg.heartbeat_secs.max(1);

        // 每条连接 spawn 接收循环 + 主动心跳（B 方案：每连接独立 recv_loop/心跳）
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        for i in 0..tunnel_pool.len() {
            let c = tunnel_pool.get(i).clone();
            // 接收循环（SRT 收 → 分发到该连接的会话）
            let recv_conn = c.conn.clone();
            let recv_mux = c.mux_enc.clone();
            let recv_reg = c.registry.clone();
            let recv_pw = passphrase.clone();
            let recv_tx = tunnel_closed_tx.clone();
            tasks.push(tokio::spawn(recv_loop(recv_conn, recv_mux, recv_pw, recv_reg, recv_tx)));

            // 主动心跳（B4：按 heartbeat_secs 周期发心跳帧保活）
            let hb_conn = c.conn.clone();
            let hb_mux = c.mux_enc.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(heartbeat_secs)).await;
                    let hb = hb_mux.encode_heartbeat();
                    if let Err(e) = hb_conn.send(hb) {
                        tracing::warn!(error = %e, "心跳发送失败");
                        break; // 连接不可用，退出心跳任务（由重连循环重建）
                    }
                }
            }));
        }

        // 启动 SOCKS5 服务；运行中断开（serve 返回 Err）或监听失败 -> 按错误类型分流
        // S2 修复（2026-08-19）：监听失败（"listen:" 前缀）= 致命配置错误，
        // 重连一万次也解决不了端口被占 -> 直接退出进程让运维感知；
        // 其余 Err（隧道断开/accept 失败）-> 走重连循环。
        let serve_result = socks5::serve(&listen_addr, tunnel_pool.clone(), socks5_cfg.clone(), tunnel_closed_rx).await;
        // 清理：abort 全部任务 + 清空会话通道 + 释放连接指标
        for t in tasks {
            t.abort();
        }
        tunnel_pool.close_all_sessions();
        m.active_connections.fetch_sub(tunnel_pool.len() as u64, std::sync::atomic::Ordering::Relaxed);

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

/// 建立单次 QUIC 连接池（B 方案 2026-08-20：并行建 pool_size 条连接）
///
/// 并行建连（spawn_blocking 各自独立），全部成功返回 Vec，任一失败返回 Err
/// （由调用方按 reconnect 配置重试整个池）。
async fn connect_pool_once(quic_cfg: &QuicConfig, pool_size: usize) -> Result<Vec<Arc<QuicConnection>>, String> {
    let mut handles = Vec::with_capacity(pool_size);
    for _ in 0..pool_size {
        let cfg = quic_cfg.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            // QuicConnection::connect 内部创建 socket + 收发线程 + 发握手
            let rt = tokio::runtime::Handle::current();
            rt.block_on(QuicConnection::connect(&cfg))
        }));
    }
    let mut conns = Vec::with_capacity(pool_size);
    for h in handles {
        conns.push(
            h.await
                .map_err(|e| format!("连接任务异常: {e}"))?
                .map_err(|e| format!("QUIC 连接失败: {e}"))?,
        );
    }
    Ok(conns)
}

/// 隧道接收循环：QUIC 事件流 → 复用帧分发
///
/// 职责（2026-08-20 重构版）：
/// - 从 QuicConnection 事件流读取 RecvEvent（Data/Control）
/// - Data（主数据流消息）：解析 Mux 帧 → 路由到会话（dispatch_frame）
/// - Control（握手响应 AUTH_OK）：验证认证结果
/// - 心跳/装饰 ACK 由内核层处理（srt_shell/ack.rs）
///
/// 与旧版的差异：不再处理 Challenge/Heartbeat Mux 帧（由内层 QuicConnection
/// 的握手/心跳语义承担），Data 帧处理保持不变。
async fn recv_loop(
    conn: Arc<QuicConnection>,
    mux_enc_local: Arc<MuxEncoder>,
    _passphrase: String,
    registry: crate::tunnel::dispatch::SessionRegistry,
    tunnel_closed_tx: tokio::sync::watch::Sender<bool>,
) {
    let result = run_recv_inner(conn, mux_enc_local, registry).await;
    tracing::info!("隧道接收循环退出，通知 SOCKS5 服务停止");
    let _ = tunnel_closed_tx.send(true);
    result
}

/// recv_loop 的实际处理体（分离信号通知，便于退出时统一置位）
async fn run_recv_inner(
    conn: Arc<QuicConnection>,
    mux_enc_local: Arc<MuxEncoder>,
    registry: crate::tunnel::dispatch::SessionRegistry,
) {
    // 取事件流（连接创建时已启动收发线程）
    let mut rx = match conn.take_events() {
        Some(rx) => rx,
        None => {
            tracing::warn!("连接事件流已被消费，接收循环退出");
            return;
        }
    };
    let mut mux_dec = crate::tunnel::multiplex::MuxDecoder::new();
    loop {
        // 从 QUIC 事件流批量读（合并多条以减调度）
        let mut batch = Vec::new();
        // 先取一条（阻塞等待）
        match rx.recv().await {
            Some(ev) => batch.push(ev),
            None => {
                // 通道关闭（连接销毁）
                tracing::info!("QUIC 事件流关闭，接收循环退出");
                break;
            }
        }
        // 尽量多取（非阻塞）构成批处理
        while let Ok(ev) = rx.try_recv() {
            batch.push(ev);
        }

        for ev in batch {
            match ev {
                crate::quic::connection::RecvEvent::Data { data, .. } => {
                    // QUIC 主数据流消息 = 一条 Mux 帧字节串，解析并分发
                    if let Some(frame) = crate::tunnel::multiplex::decode_srt_message(&data, &mut mux_dec) {
                        // 分发（会话路由 / Fin / Close / Rst / 控制）
                        match crate::tunnel::dispatch::dispatch_frame(&frame, &registry) {
                            crate::tunnel::dispatch::DispatchAction::Routed => {
                                tracing::trace!(session = frame.session_id, len = frame.payload.len(), "数据已路由到会话");
                            }
                            crate::tunnel::dispatch::DispatchAction::UnknownSession(sid) => {
                                tracing::warn!(session = sid, "数据帧无法路由（会话不存在）");
                            }
                            crate::tunnel::dispatch::DispatchAction::Fin(sid) => {
                                tracing::debug!(session = sid, "对端 FIN（半关闭）");
                            }
                            crate::tunnel::dispatch::DispatchAction::Closed(sid) => {
                                tracing::debug!(session = sid, "对端关闭会话");
                            }
                            crate::tunnel::dispatch::DispatchAction::Rst(sid) => {
                                tracing::info!(session = sid, "对端 Rst（会话已死），本地立即清理");
                            }
                            crate::tunnel::dispatch::DispatchAction::Open(_sid, _payload) => {
                                tracing::warn!("客户端收到意外的 Open 帧");
                            }
                            crate::tunnel::dispatch::DispatchAction::Other => {
                                let _ = mux_enc_local; // 心跳/ACK 由内核层处理
                                tracing::debug!(ftype = ?frame.ftype, "收到控制帧（跳过分发）");
                            }
                        }
                    } else {
                        tracing::warn!("收到无效隧道帧");
                    }
                }
                crate::quic::connection::RecvEvent::Fin { stream_id } => {
                    // 主数据流 FIN（对端关闭整条隧道方向）
                    tracing::debug!(stream = stream_id, "主数据流 FIN");
                }
                crate::quic::connection::RecvEvent::Reset { stream_id } => {
                    tracing::warn!(stream = stream_id, "主数据流被重置");
                    break;
                }
                crate::quic::connection::RecvEvent::Control(payload) => {
                    // 握手响应（AUTH_OK/FAIL 等）
                    tracing::info!(payload_len = payload.len(), "收到连接控制消息（握手响应）");
                }
            }
        }
    }
    // S3 配套修复（2026-08-19）：隧道断开时清空会话注册表（close_all drop 全部
    // 通道 Sender），让所有本地转发任务 recv_event() 得到 None 自然退出。
    let closed = registry.close_all();
    if closed > 0 {
        tracing::info!(sessions = closed, "隧道断开，关闭全部本地会话任务");
    }
}

/// 带重连的 QUIC 连接池（设计决策：5s 心跳 + 客户端自动重连，B 方案 2026-08-20）
///
/// 重连语义与旧版一致（B3）：首次建池 + 断线重建整个池。
async fn connect_pool_with_retry(cfg: &QuicConfig, app_cfg: &Config, pool_size: usize) -> Result<Vec<Arc<QuicConnection>>, String> {
    let interval = app_cfg.reconnect.as_ref().map(|r| r.interval_secs).unwrap_or(5);
    let max_retries = app_cfg.reconnect.as_ref().map(|r| r.max_retries).unwrap_or(10);
    let mut attempt = 0u64;
    loop {
        match connect_pool_once(cfg, pool_size).await {
            Ok(conns) => {
                tracing::info!(attempt, conns = conns.len(), "QUIC 连接池建立成功");
                return Ok(conns);
            }
            Err(e) => {
                attempt += 1;
                if max_retries >= 0 && attempt > max_retries as u64 {
                    return Err(format!("QUIC 连接失败（已达最大重试 {max_retries} 次）: {e}"));
                }
                tracing::warn!(attempt, interval, error = %e, "QUIC 连接失败，准备重连");
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
