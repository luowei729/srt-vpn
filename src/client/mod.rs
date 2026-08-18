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
    // 解析服务器地址（host:port）
    let peer_addr = parse_addr(&server_addr)?;

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
        pbkeylen: crypto_to_pbkeylen(&cfg.crypto),
        streamid: Some(streamid),
        rcv_latency: 1000,
        reliable: true, // 客户端跟随服务端协商，默认可靠
        message_api: true,
        payload_size: 1316, // SRT 官方默认 payload（SRT_LIVE_DEF_PLSIZE=1316）
        is_server: false,
    };

    // 2. 建立 SRT 连接（含自动重连逻辑）
    tracing::info!(server = %server_addr, "客户端启动，正在连接服务器...");
    let conn = connect_with_retry(&srt_cfg, cfg).await?;

    // 3. 构建隧道组件（复用编码器 + 会话注册表）
    let mux_enc = Arc::new(MuxEncoder::new(true));
    let registry = crate::tunnel::dispatch::SessionRegistry::new();

    // 4. 启动 SOCKS5 服务（监听 + 认证 + 会话处理）
    let socks5_cfg = cfg.socks5.clone().unwrap_or_default();
    let listen_addr = args
        .socks5_listen
        .clone()
        .unwrap_or(socks5_cfg.listen.clone());
    tracing::info!(listen = %listen_addr, "SOCKS5 服务启动");

    // 5. 启动隧道读循环（SRT 收 → 分发到会话）
    let recv_conn = Arc::new(conn);
    let passphrase = cfg.passphrase.clone();
    let recv_registry = registry.clone();
    let recv_task = tokio::spawn(recv_loop(recv_conn.clone(), mux_enc.clone(), passphrase, recv_registry));

    // 6. 启动 SOCKS5 监听（阻塞直到退出）
    let result = socks5::serve(&listen_addr, recv_conn, mux_enc, registry, socks5_cfg).await;
    let _ = recv_task.await;
    result
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
                                tracing::debug!(session = sid, "对端 FIN（半关闭），关闭会话");
                                registry.remove(sid);
                            }
                            crate::tunnel::dispatch::DispatchAction::Closed(sid) => {
                                tracing::debug!(session = sid, "对端关闭会话");
                                registry.remove(sid);
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
                                        tracing::trace!("收到心跳帧，回发");
                                        let hb = mux_enc_local.encode_heartbeat();
                                        if let Err(e) = conn.send(hb) {
                                            tracing::warn!(error = %e, "回发心跳失败");
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
async fn connect_with_retry(cfg: &SrtConfig, app_cfg: &Config) -> Result<SrtConnection, String> {
    let interval = app_cfg.reconnect.as_ref().map(|r| r.interval_secs).unwrap_or(5);
    let max_retries = app_cfg.reconnect.as_ref().map(|r| r.max_retries).unwrap_or(10);
    let mut attempt = 0u64;
    loop {
        match SrtConnection::connect(cfg) {
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

/// 解析 host:port 地址
pub fn parse_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    addr.parse()
        .map_err(|_| format!("地址格式无效: {addr}（应为 host:port）"))
}

/// 加密强度字符串 → pbkeylen 字节数
pub fn crypto_to_pbkeylen(crypto: &str) -> i32 {
    match crypto {
        "aes-128" => 16,
        "aes-192" => 24,
        "aes-256" => 32,
        _ => 16,
    }
}
