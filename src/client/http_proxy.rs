//! client/http_proxy.rs — HTTP/HTTPS 代理入口（2026-08-19 新增）
//!
//! 设计决策：
//! - 复用 SOCKS5 监听端口，通过首字节嗅探协议（0x05=SOCKS5，否则尝试 HTTP 代理）
//! - 支持：
//!   1. CONNECT 隧道（HTTPS/WebSocket）：CONNECT host:port → 建隧道 → 200 → 双向透传
//!   2. 普通 HTTP 转发（GET/POST）：解析请求，把请求头透传到隧道，双向透传
//!
//! 数据流（与 SOCKS5 相同）：
//!   客户端 HTTP 流 → 复用层 Data 帧 → SRT → 服务器直连 → 目标

use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::srt::connection::SrtConnection;
use crate::tunnel::dispatch::SessionRegistry;
use crate::tunnel::multiplex::MuxEncoder;

/// 拆分 authority（host:port），支持 IPv6 [::1]:port，无端口用默认
fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            let port = p.parse().unwrap_or(default_port);
            let host = h.trim_start_matches('[').trim_end_matches(']');
            (host.to_string(), port)
        }
        _ => {
            let host = authority.trim_start_matches('[').trim_end_matches(']');
            (host.to_string(), default_port)
        }
    }
}

/// 处理 HTTP/HTTPS 代理连接
///
/// 流程：
/// 1. 读取 HTTP 请求头（请求行 + 头部，到空行）
///    - first_byte 是协议嗅探时已读出的请求行首字符
/// 2. 解析请求行：CONNECT host:port / GET http://host:port/path / GET /path + Host 头
/// 3. 解析目标 host:port
/// 4. CONNECT：建隧道 + 回复 200 + 双向透传
///    普通 HTTP：建隧道 + 把请求头透传到隧道 + 双向透传（不预回复）
pub async fn handle_http_proxy(
    mut stream: TcpStream,
    first_byte: u8,
    peer: std::net::SocketAddr,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
) -> Result<(), String> {
    // 1. 读取 HTTP 请求头（请求行 + 头部，到空行）
    //    先把嗅探读到的首字节计入 header
    let mut header = Vec::with_capacity(8192);
    header.push(first_byte);
    let mut buf = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("读 HTTP 请求头失败: {e}"))?;
        if n == 0 {
            return Err("HTTP 请求头读取中连接关闭".to_string());
        }
        header.extend_from_slice(&buf[..n]);
        if header.windows(4).any(|w| w == b"\r\n\r\n") || header.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if header.len() > 65536 {
            return Err("HTTP 请求头过大".to_string());
        }
    }

    let header_str = String::from_utf8_lossy(&header);
    let request_line_end = header_str.find("\r\n").unwrap_or(header_str.len());
    let request_line = &header_str[..request_line_end];
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(format!("无法解析 HTTP 请求行: {request_line}"));
    }
    let method = parts[0].to_uppercase();
    let target = parts[1].to_string();

    tracing::info!(peer = %peer, method = %method, target = %target, "HTTP 代理请求");

    // 2. 解析目标 host:port
    let (dst, dst_port) = if method == "CONNECT" {
        // CONNECT host:port —— 目标在请求行的 authority
        split_host_port(&target, 443)
    } else if let Some(rest) = target.strip_prefix("http://") {
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        split_host_port(&rest[..end], 80)
    } else if let Some(rest) = target.strip_prefix("https://") {
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        split_host_port(&rest[..end], 443)
    } else {
        // 相对路径：从 Host 头取
        let host_val = header_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("host:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim())
            .unwrap_or("");
        let (h, p) = split_host_port(host_val, 80);
        (h, p)
    };

    tracing::info!(peer = %peer, method = %method, dst = %format!("{dst}:{dst_port}"), "HTTP 代理建立连接");

    // 3. 找到头结束位置（prepend 起点：头之后的数据才是需要透传到隧道的）
    let hdr_end = if let Some(pos) = header.windows(4).position(|w| w == b"\r\n\r\n") {
        pos + 4
    } else if let Some(pos) = header.windows(2).position(|w| w == b"\n\n") {
        pos + 2
    } else {
        header.len()
    };

    if method == "CONNECT" {
        // CONNECT 隧道：回复 200，头之后的字节（TLS ClientHello 等）透传到隧道
        let reply: Vec<u8> = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
        let tunnel_prepend = header[hdr_end..].to_vec();
        crate::client::proxy::start_forward_with_reply(
            stream, dst, dst_port, conn, mux_enc, registry, &reply, &tunnel_prepend,
        )
        .await
    } else {
        // 普通 HTTP：不预回复（空 reply），把完整请求头（含可能已读的 body）透传到隧道
        // 注：header 已含请求行+头，目标需要它们。这里整个 header 作为 prepend。
        let prepend = header[..].to_vec();
        crate::client::proxy::start_forward_with_reply(
            stream, dst, dst_port, conn, mux_enc, registry, &[], &prepend,
        )
        .await
    }
}
