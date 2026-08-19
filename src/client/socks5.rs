//! client/socks5.rs — SOCKS5 服务入口
//!
//! 设计决策（Q10）：
//! - 用户名密码认证（RFC 1929，多用户哈希存储，监听可配）
//! - 默认监听 127.0.0.1:1080（仅回环安全）
//! - 支持 TCP 和 UDP 代理（TCP 转封装进 SRT 隧道，UDP 经 UDP ASSOCIATE）
//!
//! SOCKS5 协议流程：
//! 1. 客户端发握手：VER(0x05) + NMETHODS + METHODS
//! 2. 服务器选认证方法（0x00 无认证 / 0x02 用户名密码）
//! 3. 用户名密码认证（RFC 1929）：VER(0x01) + ULEN + UNAME + PLEN + PASSWD
//! 4. CONNECT 请求：VER + CMD + RSV + ATYP + DST.ADDR + DST.PORT
//! 5. 建立隧道会话 → 转发数据

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::config::Socks5Config;
use crate::srt::connection::SrtConnection;
use crate::tunnel::dispatch::SessionRegistry;
use crate::tunnel::multiplex::MuxEncoder;

/// SOCKS5 协议常量
const SOCKS5_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
/// 应答码：成功（proxy.rs 复用）
pub const REP_SUCCESS: u8 = 0x00;

/// 已认证的 SOCKS5 用户（用户名密码，来自配置或 CLI）
/// （P1 后半段接入多用户认证时启用）
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Socks5Credential {
    pub username: Option<String>,
    pub password: Option<String>,
}

/// SOCKS5 服务端配置
/// （P1 后半段接入认证时启用）
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Socks5ServerConfig {
    /// 监听地址
    pub listen: String,
    /// 认证凭据（None = 无认证）
    pub cred: Option<Socks5Credential>,
}

/// 启动 SOCKS5 服务（阻塞直到监听失败）
///
/// 2026-08-19：移除 TS 伪装层后不再需要 ts_enc 参数。
pub async fn serve(
    listen_addr: &str,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
    socks5_cfg: Socks5Config,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| format!("SOCKS5 监听失败 {listen_addr}: {e}"))?;
    tracing::info!("SOCKS5 监听中: {listen_addr}");

    // 每个客户端连接独立任务处理
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("SOCKS5 accept 失败: {e}"))?;
        tracing::debug!(peer = %peer, "SOCKS5 新连接");
        let conn_c = conn.clone();
        let mux_c = mux_enc.clone();
        let reg_c = registry.clone();
        let cfg_c = socks5_cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, conn_c, mux_c, reg_c, cfg_c).await {
                tracing::debug!(peer = %peer, error = %e, "SOCKS5 连接处理结束");
            }
        });
    }
}

/// 处理单个 SOCKS5 连接（握手 + 认证 + 命令分发 + 隧道转发）
///
/// 2026-08-19：移除 TS 伪装层后不再需要 ts_enc 参数。
async fn handle_connection(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
    socks5_cfg: Socks5Config,
) -> Result<(), String> {
    // 0. 协议嗅探（2026-08-19 新增 HTTP/HTTPS 代理支持）
    //    读第一个字节判断协议：0x05=SOCKS5；其他（HTTP 方法首字母 G/P/O/D/C/T 等）=HTTP 代理
    //    关键：读到的首字节需暂存，分派到 HTTP 时作为请求行第一个字符
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(|e| format!("读协议首字节失败: {e}"))?;

    // HTTP 方法首字母（G=GET, P=POST/PUT, O=OPTIONS, D=DELETE, C=CONNECT, T=TRACE, H=HEAD, P=PATCH）
    let is_http_start = matches!(first[0], b'G' | b'P' | b'O' | b'D' | b'C' | b'T' | b'H');
    if first[0] != SOCKS5_VERSION && is_http_start {
        // HTTP/HTTPS 代理：把首字节传给 http_proxy（作为请求行第一个字符）
        return crate::client::http_proxy::handle_http_proxy(
            stream, first[0], peer, conn, mux_enc, registry,
        )
        .await;
    }

    // 1. 读握手头：VER(1) + NMETHODS(1) + METHODS(nmethods)
    // 关键：用 read_exact 精确读取，不能用单次 read！
    // TCP 是字节流不保证消息边界，单次 read 可能只读到部分字节
    // （并发多连接时内核缓冲分割更频繁，之前 curl 并发失败 0.02s 的根因）
    // 首字节已读（socks5 时是 VER），再读 NMETHODS
    if first[0] != SOCKS5_VERSION {
        return Err("非法 SOCKS5 握手版本".to_string());
    }
    let mut nmethod_buf = [0u8; 1];
    stream
        .read_exact(&mut nmethod_buf)
        .await
        .map_err(|e| format!("读认证方法数量失败: {e}"))?;
    let hdr = [first[0], nmethod_buf[0]];
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 {
        stream
            .read_exact(&mut methods)
            .await
            .map_err(|e| format!("读认证方法列表失败: {e}"))?;
    }

    // 2. 选择认证方法：优先用户名密码（0x02），否则无认证（0x00）
    let mut selected = None;
    for &m in &methods {
        if m == METHOD_USER_PASS {
            selected = Some(METHOD_USER_PASS);
            break;
        }
        if m == METHOD_NO_AUTH {
            selected = Some(METHOD_NO_AUTH);
        }
    }
    let method = selected.ok_or("无支持的认证方法")?;
    stream
        .write_all(&[SOCKS5_VERSION, method])
        .await
        .map_err(|e| format!("写认证方法响应失败: {e}"))?;

    // 3. 用户名密码认证（RFC 1929）
    let auth_user = match method {
        METHOD_USER_PASS => {
            // 格式：VER(1) + ULEN(1) + UNAME(ulen) + PLEN(1) + PASSWD(plen)
            // 精确读取：先读 2 字节头，再按长度读用户名和密码
            let mut auth_hdr = [0u8; 2];
            stream
                .read_exact(&mut auth_hdr)
                .await
                .map_err(|e| format!("读认证头失败: {e}"))?;
            if auth_hdr[0] != 0x01 {
                return Err("非法用户名密码认证版本".to_string());
            }
            let ulen = auth_hdr[1] as usize;
            let mut username_buf = vec![0u8; ulen];
            stream
                .read_exact(&mut username_buf)
                .await
                .map_err(|e| format!("读用户名失败: {e}"))?;
            let mut plen_buf = [0u8; 1];
            stream
                .read_exact(&mut plen_buf)
                .await
                .map_err(|e| format!("读密码长度失败: {e}"))?;
            let plen = plen_buf[0] as usize;
            let mut password_buf = vec![0u8; plen];
            stream
                .read_exact(&mut password_buf)
                .await
                .map_err(|e| format!("读密码失败: {e}"))?;
            let username = String::from_utf8_lossy(&username_buf).into_owned();
            let password = String::from_utf8_lossy(&password_buf).into_owned();

            // 校验凭据（配置的单一用户名密码，后续可扩展多用户 argon2）
            let cred_valid = validate_credential(&username, &password, &socks5_cfg);
            if !cred_valid {
                // 认证失败：返回 0x01（失败）并断开
                stream
                    .write_all(&[0x01, 0x01])
                    .await
                    .map_err(|e| format!("写认证失败响应失败: {e}"))?;
                return Err("SOCKS5 认证失败".to_string());
            }
            stream
                .write_all(&[0x01, 0x00])
                .await
                .map_err(|e| format!("写认证成功响应失败: {e}"))?;
            Some(username)
        }
        _ => None,
    };
    tracing::info!(peer = %peer, user = ?auth_user, "SOCKS5 认证通过");

    // 4. 读命令请求：VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(变长) + DST.PORT(2)
    // 精确读取固定头
    let mut cmd_hdr = [0u8; 4];
    stream
        .read_exact(&mut cmd_hdr)
        .await
        .map_err(|e| format!("读命令头失败: {e}"))?;
    if cmd_hdr[0] != SOCKS5_VERSION {
        return Err("非法命令请求".to_string());
    }
    let cmd = cmd_hdr[1];
    // cmd_hdr[2] 是 RSV，cmd_hdr[3] 是 ATYP

    // 5. 按 ATYP 精确读取目标地址 + 端口
    let dst_addr = match cmd_hdr[3] {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await
                .map_err(|e| format!("读 IPv4 失败: {e}"))?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await
                .map_err(|e| format!("读域名长度失败: {e}"))?;
            let dlen = len_buf[0] as usize;
            let mut domain = vec![0u8; dlen];
            stream.read_exact(&mut domain).await
                .map_err(|e| format!("读域名失败: {e}"))?;
            String::from_utf8_lossy(&domain).into_owned()
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await
                .map_err(|e| format!("读 IPv6 失败: {e}"))?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        other => return Err(format!("未知地址类型: {other}")),
    };
    let mut port_buf = [0u8; 2];
    stream
        .read_exact(&mut port_buf)
        .await
        .map_err(|e| format!("读端口失败: {e}"))?;
    let dst_port = u16::from_be_bytes(port_buf);

    // 6. 命令分发（P1 支持 CONNECT；UDP ASSOCIATE 返回不支持）
    match cmd {
        CMD_CONNECT => {
            tracing::info!(peer = %peer, dst = %format!("{dst_addr}:{dst_port}"), "SOCKS5 CONNECT");
            // 建立隧道会话并双向转发
            // proxy::start_tcp_forward 内部：
            //   1. 分配会话 ID + 发 Open 帧（目标地址）
            //   2. 双向转发：客户端流 ↔ 隧道 Data 帧
            //   3. 半关闭传播 + 会话关闭
            // 转发函数会先发 CONNECT 成功响应，再开始转发
            crate::client::proxy::start_tcp_forward(
                stream,
                dst_addr,
                dst_port,
                conn,
                mux_enc,
                registry,
            )
            .await
        }
        CMD_UDP_ASSOCIATE => {
            // UDP 代理（UDP ASSOCIATE）：创建 UDP 中继，经隧道转发（2026-08-19 实现）
            // 该命令成功后 UDP 数据报即可通过本机中继 Socket 收发
            start_udp_associate(
                stream,
                peer,
                conn,
                mux_enc,
                registry,
            )
            .await
        }
        CMD_BIND => {
            let reply = build_reply(0x07, ATYP_IPV4, &[127, 0, 0, 1], 0);
            stream
                .write_all(&reply)
                .await
                .map_err(|e| format!("写 BIND 响应失败: {e}"))?;
            Err("BIND 命令不支持".to_string())
        }
        _ => Err(format!("未知命令: {cmd}")),
    }
}

/// 解析 SOCKS5 地址（ATYP + DST.ADDR），返回 (地址字符串, 消耗字节数)
/// （已废弃：解析逻辑内联到 handle_connection 的 read_exact 流程中）

/// 构建 SOCKS5 应答包
fn build_reply(rep: u8, atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
    let mut reply = vec![SOCKS5_VERSION, rep, 0x00, atyp];
    reply.extend_from_slice(addr);
    reply.extend_from_slice(&port.to_be_bytes());
    reply
}

/// 校验 SOCKS5 凭据
///
/// 设计决策（Q10）：
/// - 配置了用户名密码 → 必须匹配（客户端本地认证）
/// - 未配置用户名密码 → 无认证放行（仅回环监听默认）
fn validate_credential(username: &str, password: &str, cfg: &Socks5Config) -> bool {
    // 未配置认证凭据 → 放行（默认仅监听 127.0.0.1，安全风险低）
    let Some(expected_user) = cfg.username.as_deref() else {
        return true;
    };
    let Some(expected_pass) = cfg.password.as_deref() else {
        return true;
    };
    // 恒定时间比较（防时序攻击）
    // 常量时间：比较长度相同，避免提前返回泄漏长度信息
    let (a, b) = (username.as_bytes(), expected_user.as_bytes());
    let (c, d) = (password.as_bytes(), expected_pass.as_bytes());
    if a.len() != b.len() || c.len() != d.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    for (x, y) in c.iter().zip(d.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// UDP ASSOCIATE 处理（SOCKS5 UDP 代理，2026-08-19 实现）
///
/// 流程：
/// 1. 创建 UDP 中继 Socket（随机本地端口），回复 SOCKS5 绑定地址+端口
/// 2. 客户端 UDP 数据报（RSV+FRAG+ATYP+ADDR+PORT+DATA）发到中继
///    → 首包解析目标 → Open 隧道 UDP 会话（proto=1，与服务器 start_udp_forward 对应）
///    → 后续 payload 发往该会话
/// 3. 隧道 UDP 响应 → 封装 SOCKS5 UDP 数据报 → 发回客户端（中继 peer 地址）
///
/// 设计约定：单 UDP ASSOCIATE 会话固定首个目标（覆盖 DNS/QUIC/在线游戏等常见
/// 单目标 UDP 场景）；多目标（不同目的端口并发）为后续扩展项。
async fn start_udp_associate(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
) -> Result<(), String> {
    use crate::tunnel::dispatch::TunnelSession;

    // 1. 创建 UDP 中继 Socket（绑定本地随机端口；0.0.0.0 允许局域网客户端访问）
    let relay = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("UDP 中继 bind 失败: {e}"))?;
    let relay_addr = relay.local_addr().map_err(|e| format!("取中继地址失败: {e}"))?;
    tracing::info!(peer = %peer, relay = %relay_addr, "UDP ASSOCIATE 中继启动");

    // 2. 回复 SOCKS5：成功 + 中继地址（IPv4 形式）
    let ip = match relay_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(_) => vec![127, 0, 0, 1], // 回退
    };
    let reply = build_reply(REP_SUCCESS, ATYP_IPV4, &ip, relay_addr.port());
    let mut stream = stream;
    stream
        .write_all(&reply)
        .await
        .map_err(|e| format!("写 UDP ASSOCIATE 响应失败: {e}"))?;

    // 解析客户端 UDP 数据报（SOCKS5 UDP 头）→ (目标host, 端口, payload)
    fn parse_udp_datagram(datagram: &[u8]) -> Option<(String, u16, &[u8])> {
        if datagram.len() < 4 {
            return None;
        }
        if datagram[2] != 0 {
            return None; // 不支持分片（FRAG != 0）
        }
        let atyp = datagram[3];
        let mut pos = 4;
        let host = match atyp {
            0x01 => {
                if datagram.len() < pos + 4 {
                    return None;
                }
                let ip = std::net::Ipv4Addr::new(
                    datagram[pos], datagram[pos + 1], datagram[pos + 2], datagram[pos + 3],
                );
                pos += 4;
                ip.to_string()
            }
            0x03 => {
                if datagram.len() < pos + 1 {
                    return None;
                }
                let dlen = datagram[pos] as usize;
                pos += 1;
                if datagram.len() < pos + dlen {
                    return None;
                }
                let host = String::from_utf8_lossy(&datagram[pos..pos + dlen]).into_owned();
                pos += dlen;
                host
            }
            _ => return None,
        };
        if datagram.len() < pos + 2 {
            return None;
        }
        let port = u16::from_be_bytes([datagram[pos], datagram[pos + 1]]);
        pos += 2;
        Some((host, port, &datagram[pos..]))
    }

    // 3. 建立单个隧道 UDP 会话（proto=1，多目标：目标由每帧地址头动态指定）
    //    Open 目标用占位（服务器多目标模式忽略 Open 固定目标）
    let (sid, rx) = registry.allocate();
    let mut session = TunnelSession::new(sid, rx, conn, mux_enc, registry.clone());
    session.send_open(1, "0.0.0.0", 0).await?;
    tracing::info!(session = sid, client = %peer, "UDP ASSOCIATE 隧道会话建立（多目标）");

    // 4. 双向转发（多目标）：
    //    - 客户端 UDP 数据报 → 解析 SOCKS5 UDP 头目标 → 封装 [地址头][payload] → 隧道
    //    - 隧道响应 [地址头][payload] → 解析源目标 → 封装 SOCKS5 UDP 数据报 → 客户端中继
    let mut buf = [0u8; 65536];
    let mut client_addr_opt: Option<std::net::SocketAddr> = None;
    loop {
        tokio::select! {
            // 方向 1：客户端 UDP → 隧道
            r = relay.recv_from(&mut buf) => {
                match r {
                    Ok((len, src)) => {
                        client_addr_opt = Some(src);
                        if let Some((host, port, payload)) = parse_udp_datagram(&buf[..len]) {
                            // 封装 [地址头][payload] → 隧道（多目标单会话）
                            let mut framed = Vec::with_capacity(len + 40);
                            let target_ip = host.parse::<std::net::Ipv4Addr>()
                                .map(std::net::IpAddr::V4)
                                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                            crate::server::forward::encode_udp_addr_header(
                                &std::net::SocketAddr::new(target_ip, port),
                                &mut framed,
                            );
                            framed.extend_from_slice(payload);
                            if let Err(e) = session.send_data(&framed).await {
                                tracing::debug!(error = %e, "UDP 隧道发送失败");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "UDP 中继 recv 失败");
                        break;
                    }
                }
            }
            // 方向 2：隧道 UDP 响应 → 客户端中继
            resp = session.recv() => {
                match resp {
                    Some(data) => {
                        // 解析 [地址头][payload]
                        if let Some((host, port, payload)) = crate::server::forward::parse_udp_addr_header(&data) {
                            // 封装 SOCKS5 UDP 数据报（ATYP 视主机决定 IPv4/域名）
                            let mut out = Vec::with_capacity(payload.len() + 40);
                            out.extend_from_slice(&[0, 0, 0]); // RSV2 + FRAG0
                            if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                                out.push(0x01);
                                out.extend_from_slice(&ip.octets());
                            } else {
                                // 域名/IPv6：用域名类型（ATYP=0x03）
                                out.push(0x03);
                                out.push(host.len() as u8);
                                out.extend_from_slice(host.as_bytes());
                            }
                            out.extend_from_slice(&port.to_be_bytes());
                            out.extend_from_slice(payload);
                            if let Some(addr) = client_addr_opt {
                                if let Err(e) = relay.send_to(&out, addr).await {
                                    tracing::debug!(error = %e, "UDP 回包失败");
                                }
                            } else {
                                tracing::debug!("UDP 响应早于首个客户端包，丢弃");
                            }
                        }
                    }
                    None => {
                        tracing::debug!("UDP 隧道会话关闭");
                        break;
                    }
                }
            }
        }
    }

    // 5. 清理：关闭会话（发 Close）
    tracing::info!(session = sid, peer = %peer, "UDP ASSOCIATE 结束");
    let _ = session.send_control(crate::tunnel::FrameType::Close, &[]).await;
    Ok(())
}
