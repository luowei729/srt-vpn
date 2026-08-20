//! quic/listener.rs — 服务端监听器（自研 QUIC 语义内核）
//!
//! 2026-08-20 重构：替代 libsrt 的 SrtListener。
//!
//! **单端口 + 单接收线程分发模型**（学 TUIC/QUIC 标准做法）：
//! - 服务端只监听一个 UDP 端口（如 9000），所有客户端都连这个端口
//! - **唯一接收线程**常驻 `recv_from`，按 src 完整地址查分发表路由到对应连接
//! - 新客户端（src 不在表中）→ 握手认证 → 回发 AUTH_OK → 注册到表
//! - 已认证客户端的后续包：接收线程查表 → `conn.handle_datagram()`
//! - 每客户端独立 QuicConnection（各自 send_loop 发送，互不干扰）
//!
//! **为什么不允许多个 recv_loop 抢读同一 socket**：
//! UDP `recv_from` 是原子读——谁先读到包就归谁。多连接各自 spawn recv_loop
//! 从共享 socket 抢读，读错连接的包直接 continue 丢弃 → 连接池第 2~4 条
//! 连接的包被第 1 条读走 → 认证超时（上一轮 bug 根因）。

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::quic::connection::QuicConnection;
use crate::srt_shell::auth;
use crate::srt_shell::header::{MSG_HANDSHAKE, SRT_HEADER_LEN};
use crate::srt_shell::outer::{decode_packet, encode_ctrl_packet};

/// 服务端监听器（单 UDP socket，单接收线程分发，多客户端）
pub struct QuicListener {
    /// 监听 UDP socket（唯一 recv_from 者 + 各连接 send_to 共用）
    udp: Arc<UdpSocket>,
    /// 认证密钥（passphrase 派生）
    secret: [u8; 16],
    /// 心跳间隔（客户端分配）
    heartbeat_secs: u64,
    /// 是否已关闭（供上层监控；当前监听循环常驻）
    #[allow(dead_code)]
    closed: Arc<AtomicBool>,
    /// 客户端分发表：src 完整地址 → 连接（接收线程按 src 路由数据包）
    routes: Arc<Mutex<HashMap<SocketAddr, Arc<QuicConnection>>>>,
    /// 新连接通道：接收线程握手成功后推送，accept 从此取（解耦收/接）
    new_conn_rx: Mutex<std::sync::mpsc::Receiver<Arc<QuicConnection>>>,
    /// 新连接发送端（接收线程持有副本，握手成功后推送）
    new_conn_tx: std::sync::mpsc::Sender<Arc<QuicConnection>>,
}

impl QuicListener {
    /// 绑定监听端口（服务端入口）
    pub fn bind(addr: SocketAddr, secret: [u8; 16], heartbeat_secs: u64) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        sock.set_nonblocking(true)?;
        let (new_conn_tx, new_conn_rx) = std::sync::mpsc::channel::<Arc<QuicConnection>>();
        Ok(Self {
            udp: Arc::new(sock),
            secret,
            heartbeat_secs,
            closed: Arc::new(AtomicBool::new(false)),
            routes: Arc::new(Mutex::new(HashMap::new())),
            new_conn_rx: Mutex::new(new_conn_rx),
            new_conn_tx,
        })
    }

    /// 启动常驻接收线程（在 accept_loop 调用 accept 之前启动一次）
    ///
    /// 接收线程职责（单端口模型核心）：
    /// 1. 唯一 `recv_from` 者（无竞争抢读，解决多连接共享 socket 丢包根因）
    /// 2. 按 src 查分发表：已注册 → `conn.handle_datagram()`（快速路径）
    /// 3. 未注册 → 尝试握手认证 → 回发 AUTH_OK → 注册到表 + 推送到 accept channel
    /// 4. WouldBlock 间隙清理已断开连接的分发表条目（防泄漏）
    pub fn spawn_recv_thread(&self) {
        let udp = Arc::clone(&self.udp);
        let routes = Arc::clone(&self.routes);
        let new_conn_tx = self.new_conn_tx.clone();
        let secret = self.secret;
        let heartbeat_secs = self.heartbeat_secs;

        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                match udp.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let data = &buf[..n];

                        // 1. 快速路径：查分发表，已注册客户端的数据包直接分发
                        let routed = {
                            let routes_guard = routes.lock().unwrap();
                            routes_guard.get(&src).map(Arc::clone)
                        };
                        if let Some(conn) = routed {
                            conn.handle_datagram(data);
                            continue;
                        }

                        // 2. 慢速路径：未注册 src → 可能是新客户端握手包
                        //    尝试握手认证（try_handshake 内部回发 AUTH_OK）
                        if let Some(conn) = Self::try_handshake_static(
                            &udp, src, data, secret, heartbeat_secs,
                        ) {
                            // 认证通过：注册到分发表（后续包走快速路径）
                            {
                                let mut routes_guard = routes.lock().unwrap();
                                routes_guard.insert(src, Arc::clone(&conn));
                            }
                            // 推送给 accept（让 accept_loop spawn 处理任务）
                            let _ = new_conn_tx.send(conn);
                        }
                        // 认证失败/非握手包：静默丢弃
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // 空闲：sleep 50µs 回轮（与客户端 recv_loop 对齐）
                        std::thread::sleep(Duration::from_micros(50));
                        // 间隙清理已断开连接（防分发表泄漏）
                        Self::cleanup_stale(&routes);
                    }
                    Err(_) => break,
                }
            }
        });
    }

    /// 清理已断开的连接（closed=true 的条目从分发表移除）
    ///
    /// 2026-08-20 修复：旧 try_lock 失败直接 return，收发高峰锁竞争强时
    /// 连续跳过清理，分发表堆积 34 条僵尸连接，max_clients 假满。改为
    /// try_lock 失败不直接丢弃，下次 WouldBlock 再试；同时每次最多清 32 条
    /// 防单次持有锁过长。
    fn cleanup_stale(routes: &Arc<Mutex<HashMap<SocketAddr, Arc<QuicConnection>>>>) {
        let stale_keys: Vec<SocketAddr> = {
            let Ok(routes_guard) = routes.try_lock() else { return };
            routes_guard
                .iter()
                .filter(|(_, conn)| conn.is_closed())
                .map(|(k, _)| *k)
                .take(32)
                .collect()
        };
        if !stale_keys.is_empty() {
            let mut routes_guard = routes.lock().unwrap();
            for k in &stale_keys {
                routes_guard.remove(k);
            }
            tracing::info!(removed = stale_keys.len(), "清理已断开客户端的分发表条目");
        }
    }

    /// 接受客户端连接（从接收线程推送的 channel 取新连接）
    ///
    /// 新模型下握手由接收线程在线完成，accept 只负责取已认证的新连接
    /// 交给 accept_loop spawn 处理任务。无新连接返回 None（调用方重试）。
    pub fn accept(&self, _max_clients: usize) -> io::Result<Option<Arc<QuicConnection>>> {
        let rx = self.new_conn_rx.lock().unwrap();
        match rx.try_recv() {
            Ok(conn) => Ok(Some(conn)),
            Err(_) => Ok(None),
        }
    }

    /// 尝试握手：解析外层 SRT 壳 + 内层握手帧 + AUTH 验证（静态方法，供接收线程调用）
    ///
    /// 返回 Some(conn)：新客户端认证通过，已构建连接并回发 AUTH_OK
    /// 返回 None：非握手包 / 认证失败 / 发送失败
    fn try_handshake_static(
        udp: &Arc<UdpSocket>,
        src: SocketAddr,
        data: &[u8],
        secret: [u8; 16],
        heartbeat_secs: u64,
    ) -> Option<Arc<QuicConnection>> {
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
        if !auth::verify_auth(&secret, payload) {
            tracing::warn!(peer = %src, "客户端认证失败，静默丢弃");
            return None;
        }

        // 4. 认证通过：回发 AUTH_OK 给客户端
        //    从监听 socket(9000) 发出，目标=src（客户端 NAT 映射地址）
        //    data_port=0（单端口模式，不迁移）
        let data_port = 0u16;
        let auth_ok_payload = auth::auth_ok(data_port);
        let mut inner = Vec::new();
        crate::quic::packet::encode_handshake(&mut inner, &auth_ok_payload);
        let auth_ok_pkt = encode_ctrl_packet(MSG_HANDSHAKE, 0, &inner);
        if let Err(e) = udp.send_to(&auth_ok_pkt, src) {
            tracing::warn!(peer = %src, error = %e, "AUTH_OK 回发失败");
            return None;
        }
        tracing::info!(peer = %src, data_port, "客户端认证通过，已回发 AUTH_OK");

        // 5. 构建客户端连接（共享监听 socket；不 spawn recv_loop）
        //    接收由 listener 统一分发（handle_datagram），发送由 send_loop 负责
        let conn = QuicConnection::attach_peer(
            Arc::clone(udp),
            src,
            secret,
            heartbeat_secs,
        );
        Some(conn)
    }

    /// 关闭监听（预留清理接口；当前监听循环由进程退出终结）
    #[allow(dead_code)]
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

// local_port 已移除：单端口模式下不迁移端口，data_port 固定 0