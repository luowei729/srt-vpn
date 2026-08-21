//! SOCKS5 + HTTP 三合一代理入口模块
//!
//! 设计原因：passwall 契约要求 SOCKS5+HTTP+HTTPS 三合一同端口。
//! 通过首字节嗅探分流：
//! - 0x05 = SOCKS5 协议
//! - HTTP 方法首字母（G/P/O/D/C/T/H）= HTTP 代理
//!
//! SOCKS5 遵循 RFC 1928，支持 CONNECT（TCP）和 UDP ASSOCIATE（UDP）。
//! HTTP 代理支持 CONNECT 隧道（HTTPS）和普通 HTTP 代理（透传请求头）。

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::metrics::Metrics;
use crate::transport::driver::{DriverEvent, DriverRequest};
use crate::tuic::addr::Address;

/// 启动 SOCKS5+HTTP 三合一代理服务
///
/// 监听同一端口，首字节嗅探分流 SOCKS5 / HTTP 代理。
pub async fn serve(
    listen_addr: SocketAddr,
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    mut event_rx: mpsc::UnboundedReceiver<DriverEvent>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| format!("SOCKS5 监听失败: {}", e))?;

    tracing::info!(addr = %listen_addr, "SOCKS5+HTTP 代理服务已启动");

    loop {
        tokio::select! {
            // 接受新连接
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        let req_tx = req_tx.clone();
                        let metrics = metrics.clone();
                        tokio::spawn(async move {
                            // 首字节嗅探分流
                            if let Err(e) = handle_connection(stream, peer_addr, req_tx, metrics).await {
                                tracing::debug!(?peer_addr, error = %e, "代理连接处理结束");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept 失败");
                    }
                }
            }
            // 监听传输层事件（保持 event_rx 活跃，处理下行数据事件）
            event = event_rx.recv() => {
                match event {
                    Some(e) => {
                        // 传输层事件：v2 驱动器事件流（流数据由 pending read 机制直达 reader）
                        match &e {
                            DriverEvent::StreamReadable { stream_id } => {
                                tracing::trace!(?stream_id, "传输层流可读事件");
                            }
                            DriverEvent::StreamFinished { stream_id } => {
                                tracing::trace!(?stream_id, "传输层流结束事件");
                            }
                            DriverEvent::StreamStopped { stream_id, error_code } => {
                                tracing::trace!(?stream_id, error_code, "传输层流重置事件");
                            }
                            DriverEvent::Connected => {
                                tracing::debug!("传输层连接已建立");
                            }
                            DriverEvent::ConnectionLost { reason } => {
                                tracing::warn!(%reason, "传输层连接丢失");
                            }
                        }
                    }
                    None => {
                        tracing::info!("传输层事件通道关闭，代理服务退出");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// 处理单个连接（首字节嗅探分流）
async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    // 读取首字节
    let first_byte = stream
        .read_u8()
        .await
        .map_err(|e| format!("读取首字节失败: {}", e))?;

    // 根据首字节分流
    if first_byte == 0x05 {
        // SOCKS5 协议
        handle_socks5(stream, first_byte, req_tx, metrics).await
    } else if is_http_method_byte(first_byte) {
        // HTTP 代理（CONNECT / GET / POST / PUT / DELETE / OPTIONS / HEAD）
        handle_http_proxy(stream, first_byte, req_tx, metrics).await
    } else {
        // 未知协议
        tracing::debug!(?peer_addr, byte = first_byte, "未知协议首字节");
        Ok(())
    }
}

/// 判断是否为 HTTP 方法首字母
fn is_http_method_byte(b: u8) -> bool {
    // HTTP 方法首字母：GET(G)/POST(P)/PUT(P)/DELETE(D)/OPTIONS(O)/CONNECT(C)/HEAD(H)
    matches!(b, b'G' | b'P' | b'D' | b'O' | b'C' | b'H')
}

/// 处理 SOCKS5 协议
async fn handle_socks5(
    mut stream: TcpStream,
    first_byte: u8,
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    // SOCKS5 握手：VER(1) = first_byte=0x05, NMETHODS(1), METHODS(可变)
    let nmethods = stream
        .read_u8()
        .await
        .map_err(|e| format!("读取 SOCKS5 NMETHODS 失败: {}", e))?;

    let mut methods = vec![0u8; nmethods as usize];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|e| format!("读取 SOCKS5 METHODS 失败: {}", e))?;

    // 选择认证方法：总是选 0x00（无认证）
    // 本地 SOCKS5 认证与 TUIC 认证不同：TUIC 认证由 QUIC 连接建立时完成
    // 若需本地 SOCKS5 认证，应在此按 config.socks5.username 决定方法（P1 未接入）
    stream
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|e| format!("发送 SOCKS5 方法选择失败: {}", e))?;

    // 读取 SOCKS5 请求：VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(可变) DST.PORT(2)
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| format!("读取 SOCKS5 请求头失败: {}", e))?;

    if header[0] != 0x05 {
        return Err(format!("SOCKS5 版本号错误: {}", header[0]));
    }

    let cmd = header[1];
    let atyp = header[3];

    // 解析目标地址
    let addr = read_socks5_address(&mut stream, atyp).await?;

    match cmd {
        0x01 => {
            // CONNECT（TCP 代理）
            tracing::info!(?addr, "SOCKS5 CONNECT 请求");
            // 回复成功
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|e| format!("SOCKS5 回复失败: {}", e))?;

            metrics.inc_sessions();
            // 进入 TCP 代理转发
            crate::client::proxy::handle_tcp_connect(stream, addr, req_tx, metrics).await
        }
        0x03 => {
            // UDP ASSOCIATE（UDP 代理）
            // 回复成功，绑定地址为 0.0.0.0:0（客户端用此地址发 UDP）
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|e| format!("SOCKS5 UDP ASSOCIATE 回复失败: {}", e))?;

            metrics.inc_sessions();
            // UDP 代理转发（通过 TUIC Packet 命令）
            crate::client::proxy::handle_udp_associate(stream, addr, req_tx, metrics).await
        }
        _ => {
            // 不支持的命令
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .ok();
            Err(format!("不支持的 SOCKS5 命令: {}", cmd))
        }
    }
}

/// 读取 SOCKS5 地址（ATYP + DST.ADDR + DST.PORT）
async fn read_socks5_address(
    stream: &mut TcpStream,
    atyp: u8,
) -> Result<Address, String> {
    match atyp {
        0x01 => {
            // IPv4：4B IP + 2B port
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.map_err(|e| format!("读取 IPv4 失败: {}", e))?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await.map_err(|e| format!("读取端口失败: {}", e))?;
            let port = u16::from_be_bytes(port_buf);
            Ok(Address::ipv4(std::net::Ipv4Addr::from(ip), port))
        }
        0x03 => {
            // 域名：1B len + domain + 2B port
            let len = stream.read_u8().await.map_err(|e| format!("读取域名长度失败: {}", e))? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await.map_err(|e| format!("读取域名失败: {}", e))?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await.map_err(|e| format!("读取端口失败: {}", e))?;
            let port = u16::from_be_bytes(port_buf);
            let domain = String::from_utf8(domain).map_err(|_| "域名非UTF-8".to_string())?;
            Ok(Address::domain(domain, port))
        }
        0x04 => {
            // IPv6：16B IP + 2B port
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await.map_err(|e| format!("读取 IPv6 失败: {}", e))?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await.map_err(|e| format!("读取端口失败: {}", e))?;
            let port = u16::from_be_bytes(port_buf);
            Ok(Address::ipv6(std::net::Ipv6Addr::from(ip), port))
        }
        _ => Err(format!("不支持的 SOCKS5 ATYP: {}", atyp)),
    }
}

/// 处理 HTTP 代理
///
/// 支持两种模式：
/// - CONNECT 隧道（HTTPS）：回 200 后透传
/// - 普通 HTTP 代理：透传请求头
async fn handle_http_proxy(
    mut stream: TcpStream,
    first_byte: u8,
    req_tx: mpsc::UnboundedSender<DriverRequest>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    // 读取 HTTP 请求行（首字节已读，补全剩余部分）
    let mut buf = vec![first_byte];
    // 读取直到 \r\n（HTTP 请求行结束）
    loop {
        let b = stream
            .read_u8()
            .await
            .map_err(|e| format!("读取 HTTP 请求行失败: {}", e))?;
        buf.push(b);
        if buf.ends_with(b"\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err("HTTP 请求行过长".into());
        }
    }

    let request_line = String::from_utf8_lossy(&buf);
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err("HTTP 请求行格式错误".into());
    }

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT 隧道（HTTPS）：target = host:port
        let addr = parse_host_port(target)?;
        // 回复 200 Connection Established
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| format!("HTTP CONNECT 回复失败: {}", e))?;

        metrics.inc_sessions();
        // 进入 TCP 代理转发（与 SOCKS5 CONNECT 相同）
        crate::client::proxy::handle_tcp_connect(stream, addr, req_tx, metrics).await
    } else {
        // 普通 HTTP 代理：target = http://host:port/path
        // 解析 URL 获取目标地址
        let addr = parse_http_url(target)?;

        // 收集完整请求头（直到空行）
        // 根治死锁：旧版读掉请求头后直接丢弃，转 handle_tcp_connect 等 TCP 新数据，
        // 但 curl 发完 GET 后在等响应不会再发数据 -> 永久死锁。
        // 正确做法：把请求行+请求头收集起来，重构后作为首包数据写入 QUIC 流
        //（服务端 Connect 命令后的 leftover 通道会把它先写入目标 TCP）。
        let mut request_bytes = rewrite_request_line(&buf, target); // 请求行改写为相对路径
        loop {
            let mut line_buf = Vec::new();
            loop {
                let b = stream
                    .read_u8()
                    .await
                    .map_err(|e| format!("读取 HTTP 头失败: {}", e))?;
                line_buf.push(b);
                if line_buf.ends_with(b"\r\n") {
                    break;
                }
                if line_buf.len() > 8192 {
                    return Err("HTTP 头过长".into());
                }
            }
            request_bytes.extend_from_slice(&line_buf);
            // 空行(\r\n)表示头结束
            if line_buf.len() == 2 {
                break;
            }
        }

        metrics.inc_sessions();
        // 带首包数据进入 TCP 代理转发（请求头作为 prepend 数据先写入 QUIC 流）
        crate::client::proxy::handle_tcp_connect_with_prepend(
            stream,
            addr,
            req_tx,
            metrics,
            request_bytes,
        )
        .await
    }
}

/// 改写 HTTP 请求行为相对路径形式（代理 -> 源服务器语义转换）
///
/// 代理收到的请求行是绝对 URL：`GET http://host:port/path HTTP/1.1\r\n`
/// 转发给源服务器必须改为相对路径：`GET /path HTTP/1.1\r\n`
/// （RFC 7230 §5.3.2：绝对形式仅用于代理；源服务器期望 origin-form）
fn rewrite_request_line(request_line: &[u8], absolute_target: &str) -> Vec<u8> {
    let line = String::from_utf8_lossy(request_line);
    let parts: Vec<&str> = line.trim_end().splitn(3, ' ').collect();
    if parts.len() == 3 {
        // 提取 URL 的 path+query 部分
        let path = if let Some(pos) = absolute_target.find("://") {
            let after_scheme = &absolute_target[pos + 3..];
            match after_scheme.find('/') {
                Some(slash) => &after_scheme[slash..],
                None => "/", // 无路径（如 http://host:port）
            }
        } else {
            absolute_target
        };
        format!("{} {} {}\r\n", parts[0], path, parts[2]).into_bytes()
    } else {
        request_line.to_vec() // 格式异常原样返回
    }
}

/// 解析 host:port 格式地址
fn parse_host_port(s: &str) -> Result<Address, String> {
    // 支持 IPv4:port / [IPv6]:port / domain:port
    if let Some(start) = s.find('[') {
        // IPv6: [::1]:port
        let end = s.find(']').ok_or("IPv6 地址缺少 ]")?;
        let ipv6_str = &s[start + 1..end];
        let port_str = &s[end + 2..]; // 跳过 ]:
        let ip: std::net::Ipv6Addr = ipv6_str.parse().map_err(|_| "IPv6 解析失败")?;
        let port: u16 = port_str.parse().map_err(|_| "端口解析失败")?;
        Ok(Address::ipv6(ip, port))
    } else {
        // IPv4:port / domain:port
        let parts: Vec<&str> = s.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("地址格式错误".into());
        }
        let port: u16 = parts[0].parse().map_err(|_| "端口解析失败")?;
        let host = parts[1];
        // 尝试解析为 IPv4
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            Ok(Address::ipv4(ip, port))
        } else {
            // 域名
            Ok(Address::domain(host, port))
        }
    }
}

/// 解析 HTTP URL 获取目标地址
fn parse_http_url(url: &str) -> Result<Address, String> {
    // 去掉 http:// 前缀
    let host_part = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    // 取 host:port 部分（去掉 path）
    let host_port = host_part.split('/').next().unwrap_or(host_part);
    parse_host_port(host_port)
}
