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
use tokio::net::{TcpListener, TcpStream};

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
            // UDP 代理（P1 后半段实现），当前返回不支持
            let reply = build_reply(0x07, ATYP_IPV4, &[127, 0, 0, 1], 0);
            stream
                .write_all(&reply)
                .await
                .map_err(|e| format!("写 UDP 响应失败: {e}"))?;
            Err("UDP ASSOCIATE 尚未支持（P1 开发中）".to_string())
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
    username == expected_user && password == expected_pass
}
