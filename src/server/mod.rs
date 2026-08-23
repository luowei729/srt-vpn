//! server/mod.rs — 服务器模块
//!
//! 设计决策（Q17/Q20）：
//! - 服务器仅 Linux，监听单端口（数据+信号共存）
//! - 支持多客户端并发：每客户端独立 SRT 连接 + 独立会话空间
//! - 出口：P1 直连转发（TCP connect / UDP sendto）；P2 iptables NAT
//! - 认证：streamid 静态令牌（第一道门）+ 双 HMAC 挑战-应答（第二道门）

pub mod forward;
pub mod listener;

use crate::config::Config;
use crate::srt::connection::SrtConfig;

/// 服务器运行入口
pub async fn run(cfg: &Config) -> Result<(), String> {
    let listen = cfg.listen.clone().ok_or("服务端配置缺少 listen 字段")?;
    let peer_addr = parse_listen_addr(&listen)?;

    // 构建监听配置（服务端：listen 模式 + 不设 streamid）
    // P1 2026-08-23：1000→120ms 降低 TTFB（与客户端一致）
    let srt_cfg = SrtConfig {
        peer_addr,
        passphrase: cfg.passphrase.clone(),
        pbkeylen: crate::config::crypto_to_pbkeylen(&cfg.crypto),
        streamid: None,
        rcv_latency: 120,
        reliable: match cfg.udp_mode {
            crate::cli::UdpMode::Reliable => true,
            crate::cli::UdpMode::BestEffort => false,
        },
        message_api: true,
        payload_size: 1316, // SRT 官方默认 payload
        // v0.5.3：UDP DATAGRAM 实验开关透传（默认 false，accept 的连接继承）
        udp_datagram: cfg.udp_datagram,
        is_server: true,
    };

    tracing::info!(listen = %listen, udp_mode = ?cfg.udp_mode, "服务端启动，等待客户端连接...");

    // 启动指标服务（如果配置了端口）
    if let Some(port) = cfg.metrics_port {
        let m = crate::metrics::metrics();
        m.active_connections.store(0, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            if let Err(e) = crate::metrics::Metrics::serve_http(port).await {
                tracing::warn!(error = %e, "指标服务异常");
            }
        });
    }

    // 多客户端监听循环：每客户端一个 accept + 独立处理任务
    listener::accept_loop(&srt_cfg, cfg).await
}

/// 解析监听地址（host:port）
pub fn parse_listen_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    addr.parse()
        .map_err(|_| format!("监听地址格式无效: {addr}（应为 host:port）"))
}
// L 级清理（2026-08-19）：crypto_to_pbkeylen 重复实现移除，统一用 config::crypto_to_pbkeylen
