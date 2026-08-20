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
use crate::quic::crypto::derive_key;

/// 服务器运行入口
pub async fn run(cfg: &Config) -> Result<(), String> {
    let listen = cfg.listen.clone().ok_or("服务端配置缺少 listen 字段")?;
    let peer_addr = parse_listen_addr(&listen)?;

    // 认证密钥：passphrase → 派生密钥（与客户端一致，作为 SRT 特征握手 AUTH 密钥）
    // 2026-08-20 重构：libsrt/SrtConfig 弃用；认证在 QuicListener 握手内完成。
    let secret: [u8; 16] = derive_key(cfg.passphrase.as_bytes(), b"srt-vpn-v3-salt", 16)
        .try_into()
        .expect("密钥长度固定 16B");
    let heartbeat_secs = cfg.heartbeat_secs.max(5);

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

    // 多客户端监听循环：QuicListener 内建 SRT 特征握手认证，accept 后独立处理任务
    listener::accept_loop(peer_addr, secret, heartbeat_secs, cfg).await
}

/// 解析监听地址（host:port）
pub fn parse_listen_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    addr.parse()
        .map_err(|_| format!("监听地址格式无效: {addr}（应为 host:port）"))
}
// L 级清理（2026-08-19）：crypto_to_pbkeylen 重复实现移除，统一用 config::crypto_to_pbkeylen
