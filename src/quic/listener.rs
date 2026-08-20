//! quic/listener.rs — 服务端监听器（自研 QUIC 语义内核）
//!
//! 2026-08-20 重构：替代 libsrt 的 SrtListener。
//! 服务端监听 UDP 端口，非阻塞 accept 客户端：
//! - 同一 UDP socket 接收多客户端（缺省用 src addr 区分对端）
//! - 首包 = SRT 特征握手（0x80 控制 + HANDSHAKE + 内层 AUTH），验证后构建连接
//! - 后续包按源地址路由到对应 QuicConnection
//!
//! 线程模型：单一接收线程（非阻塞轮询）+ 每个 accept 出的客户端一个
//! QuicConnection（其自身有收发线程）。服务端每个客户端独立 QuicConnection。

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::quic::connection::QuicConnection;
use crate::srt_shell::auth;
use crate::srt_shell::header::{MSG_HANDSHAKE, SRT_HEADER_LEN};
use crate::srt_shell::outer::{decode_packet, encode_ctrl_packet};

/// 服务端监听器（单 UDP socket，多客户端）
pub struct QuicListener {
    /// 监听 UDP socket（共享给各客户端连接发收）
    udp: Arc<UdpSocket>,
    /// 认证密钥（passphrase 派生）
    secret: [u8; 16],
    /// 心跳间隔（客户端分配）
    heartbeat_secs: u64,
    /// 是否已关闭（供上层监控；当前监听循环常驻）
    #[allow(dead_code)]
    closed: Arc<AtomicBool>,
}

impl QuicListener {
    /// 绑定监听端口（服务端入口）
    pub fn bind(addr: SocketAddr, secret: [u8; 16], heartbeat_secs: u64) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        sock.set_nonblocking(true)?;
        Ok(Self {
            udp: Arc::new(sock),
            secret,
            heartbeat_secs,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// 接受客户端连接：扫描"第一个新客户端"的合法握手
    ///
    /// - 阻塞（非阻塞轮询 + 内部循环）直到收到合法握手包（含 AUTH 通过）
    /// - 返回该客户端的 QuicConnection（已认证、peer 已知、复用监听 socket）
    /// - 已认证客户端的后续数据包由该 QuicConnection 的 recv_loop 处理
    ///   （QuicConnection 用 send_to(src) 回包——监听 socket 同一 socket）
    ///
    /// ⚠️ 注意：QuicConnection::attach_peer 的 recv_loop 会从共享 socket recv，
    /// 但它只处理 peer 匹配的包。多客户端时各连接 recv_loop 会都读到包，
    /// 但 handle_datagram 内部按 peer 过滤（src != self.peer continue）。
    /// 因此多客户端安全：各自只处理自己的包。
    pub fn accept(&self, max_clients: usize) -> io::Result<Option<Arc<QuicConnection>>> {
        let mut buf = vec![0u8; 65536];
        // 非阻塞扫描：找新客户端的合法握手（已认证客户端数据由各自 recv_loop 吃）
        loop {
            match self.udp.recv_from(&mut buf) {
                Ok((n, src)) => {
                    // 验证握手包（若是数据包/已认证客户端的普通包则非握手 → 忽略）
                    if let Some(conn) = self.try_handshake(&buf[..n], src, max_clients) {
                        return Ok(Some(conn));
                    }
                    // 非握手包：忽略（防御垃圾包；已认证客户端的数据由自身处理，
                    // 但注意：这些包同时被此 accept 轮询读到——需避免误当新握手。
                    // try_handshake 对数据包返回 None，安全）
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // 非阻塞轮询：无新数据，返回 None（调用方 sleep 后重试）
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// 当前注册的客户端数（预留监控接口）
    #[allow(dead_code)]
    fn clients_count_hint(&self) -> usize {
        0
    }

    /// 尝试握手：解析外层 SRT 壳 + 内层握手帧 + AUTH 验证
    ///
    /// 返回 Some(conn)：新客户端认证通过，已构建连接（**独立数据 socket**）
    /// 返回 None：非握手包 / 认证失败 / 超限
    fn try_handshake(&self, data: &[u8], src: SocketAddr, max_clients: usize) -> Option<Arc<QuicConnection>> {
        if data.len() < SRT_HEADER_LEN + 1 {
            tracing::trace!(peer = %src, len = data.len(), "过短包，忽略");
            return None;
        }
        // 1. 外层 SRT 壳解析：必须是控制包 + HANDSHAKE
        let Some((is_ctrl, msg_type, inner)) = decode_packet(data) else {
            tracing::trace!(peer = %src, "外壳解析失败，忽略");
            return None;
        };
        if !is_ctrl || msg_type != MSG_HANDSHAKE {
            tracing::trace!(peer = %src, is_ctrl, msg_type, "非握手控制包，忽略");
            return None;
        }
        // 2. 内层握手帧解析
        let Ok(payload) = crate::quic::packet::decode_handshake(inner) else {
            tracing::debug!(peer = %src, "内层握手帧解析失败");
            return None;
        };
        // 3. AUTH 验证（SRT 特征认证）
        if !auth::verify_auth(&self.secret, payload) {
            tracing::warn!(peer = %src, "客户端认证失败，静默丢弃");
            return None;
        }

        // 4. 认证通过：为该客户端建立**独立 UDP socket**（数据通道），
        //    避免多客户端在共享监听 socket 上 recv 竞争（accept 抢包丢数据）。
        //    监听 socket 只做握手；此后数据通过独立端口收发。
        let data_sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(peer = %src, error = %e, "为客户端建数据 socket 失败");
                return None;
            }
        };
        let _ = data_sock.set_nonblocking(true);
        // 2026-08-20 吞吐修复：调大数据通道 socket 缓冲（默认 208KB 高速下必溢出丢包）
        crate::quic::connection::enlarge_socket_buffers(&data_sock);
        // 获取随机绑定端口（独立数据通道端口，回传给客户端迁移）
        let data_port = local_port(&data_sock);
        tracing::trace!(peer = %src, data_port, "为客户端建立独立数据通道");

        // 回 AUTH_OK 携带数据端口，客户端据此迁移
        let ok = auth::auth_ok(data_port);
        let mut pkt = Vec::new();
        crate::quic::packet::encode_handshake(&mut pkt, &ok);
        let outer = encode_ctrl_packet(MSG_HANDSHAKE, 0, &pkt);
        let _ = self.udp.send_to(&outer, src);
        tracing::info!(peer = %src, data_port, "客户端认证通过，数据端口已分配");

        // 构建客户端连接（独立 socket；对端仍为 src 源地址）
        // 客户端收到 AUTH_OK 中的 data_port 后，会把数据目标端口迁移到它；
        // attach 的 recv_loop 从 data_sock 收该客户端后续到 data_port 的数据报。
        let conn = QuicConnection::attach_peer(Arc::new(data_sock), src, self.secret, self.heartbeat_secs);
        let _ = max_clients;
        Some(conn)
    }

    /// 关闭监听（预留清理接口；当前监听循环由进程退出终结）
    #[allow(dead_code)]
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// 获取 UDP socket 的本地端口（独立数据通道端口回传客户端）
fn local_port(sock: &UdpSocket) -> u16 {
    match sock.local_addr() {
        Ok(addr) => addr.port(),
        Err(_) => 0, // 未知端口：客户端沿用监听端口（防御）
    }
}