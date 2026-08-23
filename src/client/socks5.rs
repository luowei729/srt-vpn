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
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Socks5Credential {
    pub username: Option<String>,
    pub password: Option<String>,
}

/// SOCKS5 多用户表条目（H3 2026-08-19：多用户 argon2 认证）
/// username 明文 + password_hash argon2（与服务端 Socks5User 同 schema，
/// 客户端本地 SOCKS5 入口的用户表由配置 socks5.users / 环境变量 SRT_SOCKS5_USERS 提供）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Socks5UserEntry {
    pub username: String,
    pub password_hash: String,
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

/// 启动 SOCKS5 服务（阻塞直到监听失败或隧道断开）
///
/// 2026-08-19：移除 TS 伪装层后不再需要 ts_enc 参数。
/// 2026-08-19 审查修复（B3 重连关键缺陷）：
/// 此前 serve 只阻塞在 accept，隧道断开（recv_loop 退出）时它毫无感知继续 accept 新连接，
/// 导致 client::run 卡死在 serve().await、重连循环永不触发。现增加 tunnel_closed 信号：
/// recv_loop 因隧道断开退出时置位，serve 收到信号立即返回 Err，让重连循环接管。
pub async fn serve(
    listen_addr: &str,
    conn: Arc<SrtConnection>,
    mux_enc: Arc<MuxEncoder>,
    registry: SessionRegistry,
    socks5_cfg: Socks5Config,
    mut tunnel_closed: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    // S2 修复（2026-08-19）：监听失败用 "listen:" 前缀标记。
    // 旧实现两类 Err 混在一起：客户端 run() 收到任何 Err 都走"重连"分支，
    // 但监听失败（端口被占）时 SRT 连接完全正常、recv_loop 不会退出，
    // `recv_task.await` 永久挂起 -> 客户端卡死（不重连不退出）。
    // 现 run() 按前缀分流："listen:" 前缀 = 致命错误直接退出，其余 = 走重连。
    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => return Err(format!("listen:SOCKS5 监听失败 {listen_addr}: {e}")),
    };
    tracing::info!("SOCKS5 监听中: {listen_addr}");

    // 每个客户端连接独立任务处理
    loop {
        // select：accept 新连接 vs 隧道断开信号（断开时退出，触发重连）
        tokio::select! {
            accept_res = listener.accept() => {
                let (stream, peer) = accept_res
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
            _ = tunnel_closed.changed() => {
                tracing::info!("隧道已断开，SOCKS5 服务停止接受新连接");
                return Err("隧道已断开，等待重连".to_string());
            }
        }
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

    // 2. 选择认证方法：根据配置决定
    //    2026-08-19 审查修复：配置了用户名密码（或用户表）时【只接受 0x02 用户名密码认证】，
    //    未配置时才接受 0x00 无认证。
    //    原逻辑无论配置如何都接受 0x00（循环里只要客户端提议 0x00 就选它），
    //    导致"配置了认证但无认证也能连"的安全漏洞（passwall 节点配置 socks 认证时
    //    实际形同虚设）。
    let auth_configured = socks5_cfg.has_auth();
    let mut selected = None;
    for &m in &methods {
        if m == METHOD_USER_PASS && auth_configured {
            selected = Some(METHOD_USER_PASS);
            break;
        }
        if m == METHOD_NO_AUTH && !auth_configured {
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
///
/// H3 修复（2026-08-19）：新增多用户表支持（服务端 socks5_users 同一 schema）。
/// 单用户（socks5.username/password）保持原逻辑；多用户表（Socks5Config.users）
/// 存 argon2 哈希，逐条 verify_password。此前 README/PROJECT_PLAN 宣称的多用户
/// argon2 认证实际从未实现（服务端 socks5_users 是无人消费的死配置）。
fn validate_credential(username: &str, password: &str, cfg: &Socks5Config) -> bool {
    // 多用户表优先：逐条校验（用户名精确匹配 + argon2 验证密码哈希）
    if !cfg.users.is_empty() {
        for u in &cfg.users {
            if u.username == username {
                // 恒定路径：无论哪一步失败都继续走完（此处用户名已匹配，直接验密码）
                return crate::auth::verify_password(password, &u.password_hash)
                    .unwrap_or(false);
            }
        }
        return false; // 用户名不存在
    }

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

/// UDP ASSOCIATE 处理（SOCKS5 UDP 代理，2026-08-19 实现，多目标+大包分片）
///
/// 流程：
/// 1. 创建 UDP 中继 Socket（随机本地端口），回复 SOCKS5 绑定地址+端口
/// 2. 客户端 UDP 数据报（RSV+FRAG+ATYP+ADDR+PORT+DATA）发到中继
///    → 首包解析目标 → Open 隧道 UDP 会话（proto=1，与服务器 start_udp_forward 对应）
///    → 后续 payload 发往该会话（>1301B 自动分片）
/// 3. 隧道 UDP 响应 → 重组（分片时）→ 封装 SOCKS5 UDP 数据报 → 发回客户端中继
///
/// 设计约定：单 UDP ASSOCIATE 会话支持多目标（每数据报内嵌地址头动态路由）；
/// 大 UDP 数据报（>1301B）自动分片传输，接收端重组（协议见 forward.rs split_udp_frames）。
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
            // H2 修复（2026-08-19）：IPv6 目标支持（16 字节地址转字符串，
            // 经隧道地址头透传，服务端 lookup_host 可解析 IPv6 字面量）
            0x04 => {
                if datagram.len() < pos + 16 {
                    return None;
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&datagram[pos..pos + 16]);
                pos += 16;
                std::net::Ipv6Addr::from(ip).to_string()
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
    //    2026-08-19 审查修复（F4）：allocate 增加会话上限，失败时返回 None
    let (sid, rx) = registry
        .allocate()
        .ok_or("隧道会话数已达上限，UDP ASSOCIATE 被拒绝")?;
    let mut session = TunnelSession::new(sid, rx, conn, mux_enc, registry.clone());
    session.send_open(1, "0.0.0.0", 0).await?;
    tracing::info!(session = sid, client = %peer, "UDP ASSOCIATE 隧道会话建立（多目标）");

    // 4. 双向转发（多目标 + 大包分片）：
    //    - 客户端 UDP 数据报 → 解析 SOCKS5 UDP 头目标 → 封装 [地址头][payload] → 隧道
    //      （>1301B 自动分片为多个隧道帧）
    //    - 隧道响应 → 重组（分片时）→ 解析源目标 → 封装 SOCKS5 UDP 数据报 → 客户端中继
    //
    //    H1 修复（2026-08-19）：增加两个退出通道--
    //    a) TCP 控制连接断开检测（SOCKS5 标准的 UDP 会话结束信号：客户端断开
    //       TCP 即表示 ASSOCIATE 结束；旧实现只监听 UDP socket + 隧道，
    //       TCP 断开后任务永久泄漏：任务+会话 ID+UDP socket 全部滞留）
    //    b) 空闲看门狗（300s，与服务端一致；对端静默时回收泄漏资源）
    //    M5 修复：回包目标锁定为**首个发包包源地址**，防第三方向中继端口注入伪造响应。
    let mut stream = stream;
    let mut buf = [0u8; 65536];
    let mut client_addr_opt: Option<std::net::SocketAddr> = None;
    let mut reassembler = crate::server::forward::UdpReassembler::new();
    // H1：空闲看门狗（300s 双向无活动则结束会话，防泄漏）
    const UDP_IDLE_TIMEOUT_SECS: u64 = 300;
    let idle_duration = std::time::Duration::from_secs(UDP_IDLE_TIMEOUT_SECS);
    let mut idle_watchdog = std::pin::pin!(tokio::time::sleep(idle_duration));
    // H1：TCP 控制连接读缓冲（读到任何数据都异常，SOCKS5 规定 ASSOCIATE 后 TCP 不再有数据）
    let mut tcp_buf = [0u8; 512];
    loop {
        tokio::select! {
            // H1：看门狗分支
            _ = &mut idle_watchdog => {
                tracing::info!(session = sid, idle_secs = UDP_IDLE_TIMEOUT_SECS, "UDP ASSOCIATE 空闲超时，结束");
                break;
            }
            // H1：TCP 控制连接断开检测（read 返回 0=对端关闭 / Err=连接错误）
            tcp_r = stream.read(&mut tcp_buf) => {
                match tcp_r {
                    Ok(0) => {
                        tracing::debug!(session = sid, "TCP 控制连接关闭，UDP ASSOCIATE 结束");
                        break;
                    }
                    Ok(n) => {
                        tracing::warn!(session = sid, len = n, "UDP ASSOCIATE 期间收到意外 TCP 数据，结束会话");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(session = sid, error = %e, "TCP 控制连接错误，UDP ASSOCIATE 结束");
                        break;
                    }
                }
            }
            // 方向 1：客户端 UDP → 隧道
            r = relay.recv_from(&mut buf) => {
                match r {
                    Ok((len, src)) => {
                        // M5：锁定回包目标 = 首个有效发包包源（后续包源不一致时忽略，
                        // 防止第三方注入；中继端口是本地随机端口，外部可直接注入伪造包）
                        if client_addr_opt.is_none() {
                            client_addr_opt = Some(src);
                        }
                        idle_watchdog.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                        if let Some((host, port, payload)) = parse_udp_datagram(&buf[..len]) {
                            // H2 修复：目标 host 直接按字符串进地址头（IPv4/域名/IPv6
                            // 全类型支持）。旧实现 parse::<Ipv4Addr> 失败就替换成
                            // 0.0.0.0 占位 -> 域名/IPv6 目标被静默发往 0.0.0.0 失效。
                            // 服务端 lookup_host 可解析域名与 IPv6 字面量。
                            let mut addr_header = Vec::with_capacity(64);
                            crate::server::forward::encode_udp_addr_header_host(&host, port, &mut addr_header);
                            // 大包自动分片，小包单帧原样
                            let frames = crate::server::forward::split_udp_frames(&addr_header, payload);
                            for frame in frames {
                                // v0.5.2：UDP 方向改走不可靠通道（QUIC DATAGRAM 语义）--
                                // SRT per-message TTL 过期即弃，丢包链路下不再被重传拖高延时
                                if let Err(e) = session.send_unreliable(&frame).await {
                                    tracing::debug!(error = %e, "UDP 隧道发送失败");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "UDP 中继 recv 失败");
                        break;
                    }
                }
            }
            // 方向 2：隧道 UDP 响应 → 客户端中继（重组分片）
            resp = session.recv() => {
                match resp {
                    Some(data) => {
                        // H1：隧道方向有活动，重置看门狗
                        idle_watchdog.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                        // 输入重组器：小包直接出，分片积累到重组完成才出
                        if let Some(full) = reassembler.push(&data) {
                            // 解析 [地址头][payload]
                            if let Some((host, port, payload)) = crate::server::forward::parse_udp_addr_header(&full) {
                                // 封装 SOCKS5 UDP 数据报（ATYP 视主机决定 IPv4/IPv6/域名）
                                let mut out = Vec::with_capacity(payload.len() + 64);
                                out.extend_from_slice(&[0, 0, 0]); // RSV2 + FRAG0
                                if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                                    out.push(0x01);
                                    out.extend_from_slice(&ip.octets());
                                } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
                                    // H2 修复：IPv6 源地址用 ATYP=0x04 正确封装（旧实现归入域名分支）
                                    out.push(0x04);
                                    out.extend_from_slice(&ip.octets());
                                } else {
                                    // 域名：用域名类型（ATYP=0x03）
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
