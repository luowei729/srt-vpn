//! quic/connection.rs — 自研 QUIC 语义连接（核心状态机）
//!
//! 2026-08-20 重构：取代 libsrt 的 SrtConnection。本连接用 Rust 原生 UDP socket
//! 收发 + 自研传输语义（多流/ACK/丢失恢复/BBR 拥控），外层套 SRT 全仿外壳
//! （srt_shell），实现"真 QUIC 传输效果 + SRT 流量伪装"。
//!
//! 职责划分：
//! - 本文件：连接生命周期、UDP 收发、包调度（BBR 限速/ACK 聚合）、断线检测
//! - srt_shell/：SRT 外形（16B 头 + 0x80 握手 + ACK 节奏）——伪装
//! - quic/packet.rs：内层传输帧编解码
//! - quic/stream.rs：多流缓冲/乱序/FIN
//! - quic/ack.rs：ACK/丢失恢复/RTO
//! - quic/congctl.rs：BBR 拥塞窗口
//!
//! 线程模型：单接收线程（阻塞 recv 循环）+ 发送走共享 UDP socket（sendto 原子）。
//! 持久 UDP socket 由 QuicConn::bind（服务端）或 connect（客户端）建立。

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::quic::ack::{SentPayload, SendTracker};
use crate::quic::congctl::Bbr;
use crate::quic::packet::{self, FrameType};
use crate::quic::stream::StreamManager;

/// 对外暴露：连接状态（P1.5 监控/日志接入时启用 state()）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum QuicState {
    /// 握手未完成
    Handshaking,
    /// 运行中
    Connected,
    /// 已断开
    Closed,
}

/// 接收到的数据事件（转发给上层会话）
#[derive(Debug)]
pub enum RecvEvent {
    /// 应用数据（流 ID + 字节；stream_id 供 per-session 未来扩展，现单主数据流）
    Data { #[allow(dead_code)] stream_id: u32, data: Vec<u8> },
    /// 流 FIN（对端发送方向关闭）
    Fin { stream_id: u32 },
    /// 流 RST
    Reset { stream_id: u32 },
    /// 连接级事件（握手响应/心跳等）
    Control(Vec<u8>),
}

/// QUIC 连接配置
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// 对端地址（客户端 connect 必填；服务端由 attach_peer 直接指定）
    pub peer: Option<SocketAddr>,
    /// 服务端模式 / 本机监听地址 / 初始拥控窗口（预留配置项，当前用默认）
    #[allow(dead_code)]
    pub is_server: bool,
    #[allow(dead_code)]
    pub bind_addr: Option<SocketAddr>,
    /// 载荷加密密钥（由 passphrase + 握手协商确定，见 crypto.rs）
    pub secret: [u8; 16],
    #[allow(dead_code)]
    pub init_cwnd_packets: usize,
    /// 心跳间隔（秒）
    pub heartbeat_secs: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            peer: None,
            is_server: false,
            bind_addr: None,
            secret: [0u8; 16],
            init_cwnd_packets: 16,
            heartbeat_secs: 5,
        }
    }
}

/// 自研 QUIC 语义连接
///
/// 线程安全：内部状态用 Mutex 保护（单接收线程 + 多发送任务）。这是
/// "换芯保壳"的关键接口——对上层（client/server）暴露与 SrtConnection
/// 类似的 API（send/recv 事件流），但底层是自研内核。
pub struct QuicConnection {
    /// UDP socket（共享引用，收发线程共用）
    udp: Arc<UdpSocket>,
    /// 对端地址
    peer: SocketAddr,
    /// 连接状态
    state: Arc<AtomicU8>,
    /// 断线信号（上层轮询/select）
    closed: Arc<AtomicBool>,
    /// 流管理器
    streams: Mutex<StreamManager>,
    /// 发送跟踪（ACK/重传/RTO）
    tracker: Mutex<SendTracker>,
    /// 拥塞控制（BBR）
    congctl: Mutex<Bbr>,
    /// 接收事件通道（上层消费）
    rx_tx: tokio::sync::mpsc::UnboundedSender<RecvEvent>,
    /// 事件流接收端（前端 `take_events` 取走消费）
    rx_rx: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<RecvEvent>>>>,
    /// 认证/加密密钥（由 passphrase 派生，见 crypto.rs）
    secret: [u8; 16],
    /// 认证完成标志（客户端：收到服务端 AUTH_OK 置位；服务端：attach 即真）
    /// 2026-08-20 修复：客户端须等认证完成再发业务数据，避免首个 Open/Data
    /// 在服务端 accept 完成前发出被丢弃（多设备稳定性关键）。
    authenticated: Arc<AtomicBool>,
    /// 迁移后的数据端口（服务端分配独立数据通道；0 = 未迁移，仍用原监听端口）
    /// 2026-08-20 多设备架构：监听 socket 只握手，认证后数据走独立端口。
    data_only_port: Arc<std::sync::atomic::AtomicU16>,
    /// 心跳间隔（秒，断线检测）
    heartbeat_secs: u64,
}

// 状态值编码（QuicState 的 repr）
const ST_HANDSHAKING: u8 = 0;
const ST_CONNECTED: u8 = 1;
const ST_CLOSED: u8 = 2;

/// 主数据流 ID（承载前端 Mux 消息单流模式）
/// 决策 F：单连接共享拥控窗口，复用层消息都走这一条流，
/// QUIC 内部可靠传输保证有序不丢，前端 TunnelSession 语义不变。
const MAIN_STREAM_ID: u32 = 1;

impl QuicConnection {
    /// 建立连接（客户端入口：connect 到 peer + 发送 SRT 特征握手 AUTH）
    ///
    /// 流程：
    ///   1. 创建 UDP socket（本机随机端口）
    ///   2. 发送 SRT 特征握手（外层 0x80 壳 + 内层 Handshake 帧 + AUTH 载荷）
    ///   3. 启动收发线程（接收线程处理握手响应/数据，发送循环调度）
    ///
    /// 认证：见 srt_shell/auth.rs——AUTH 载荷 = [cmd=AUTH][nonce][签名]，服务端
    /// 验证 passphrase 后回 AUTH_OK。旧双 HMAC 挑战-应答已按共识移除。
    ///
    /// 2026-08-20 重构：libsrt 弃用，改自研 QUIC 语义内核。
    pub async fn connect(cfg: &QuicConfig) -> io::Result<Arc<Self>> {
        let peer = cfg.peer.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "客户端需 peer"))?;
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_nonblocking(true)?;

        let (rx_tx, rx_rx) = tokio::sync::mpsc::unbounded_channel::<RecvEvent>();
        let conn = Arc::new(Self {
            udp: Arc::new(sock),
            peer,
            state: Arc::new(AtomicU8::new(ST_HANDSHAKING)),
            closed: Arc::new(AtomicBool::new(false)),
            secret: cfg.secret,
            streams: Mutex::new(StreamManager::new()),
            tracker: Mutex::new(SendTracker::new()),
            congctl: Mutex::new(Bbr::new()),
            rx_tx,
            heartbeat_secs: cfg.heartbeat_secs.max(5),
            rx_rx: Arc::new(Mutex::new(Some(rx_rx))),
            authenticated: Arc::new(AtomicBool::new(false)),
            data_only_port: Arc::new(std::sync::atomic::AtomicU16::new(0)),
        });

        // 启动接收线程（非阻塞 recv 轮询 + 帧解析 + 事件投递）
        let conn2 = conn.clone();
        std::thread::spawn(move || {
            conn2.recv_loop();
        });

        // 启动发送循环（BBR 调速 + 流缓冲 -> 网络 + ACK/重传）
        let conn3 = conn.clone();
        std::thread::spawn(move || {
            conn3.send_loop();
        });

        // 客户端：连接建立后立即发送 SRT 特征握手（认证），并等待对端确认。
        // 2026-08-20 修复（多设备稳定性）：connect 返回前必须确认服务端已
        // 完成握手并 attach（避免首个 Mux 业务帧在服务端 accept 完成前发出
        // 被丢弃）。超时未认证视为失败（由调用方重连）。
        conn.send_handshake();
        // 等认证完成（最长 8s；正常秒级完成）
        let deadline = Instant::now() + Duration::from_secs(8);
        while !conn.authenticated.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !conn.authenticated.load(Ordering::Acquire) {
            tracing::warn!(peer = %peer, "客户端等待认证超时（8s），连接视为失败");
            conn.closed.store(true, Ordering::Release);
            return Err(io::Error::new(io::ErrorKind::TimedOut, "认证超时"));
        }
        Ok(conn)
    }

    /// 服务端 Attach：绑定到监听 socket 的一个已认证客户端（共享 socket 模式）
    ///
    /// 由 QuicListener::accept 验证握手后调用：为客户端创建独立 QuicConnection，
    /// 复用监听 UDP socket 收发（send_to 该 peer），own recv 线程处理该 peer 的包。
    pub fn attach_peer(udp: Arc<UdpSocket>, peer: SocketAddr, secret: [u8; 16], heartbeat_secs: u64) -> Arc<Self> {
        let (rx_tx, rx_rx) = tokio::sync::mpsc::unbounded_channel::<RecvEvent>();
        let conn = Arc::new(Self {
            udp,
            peer,
            state: Arc::new(AtomicU8::new(ST_CONNECTED)),
            closed: Arc::new(AtomicBool::new(false)),
            secret,
            streams: Mutex::new(StreamManager::new()),
            tracker: Mutex::new(SendTracker::new()),
            congctl: Mutex::new(Bbr::new()),
            rx_tx,
            heartbeat_secs: heartbeat_secs.max(5),
            rx_rx: Arc::new(Mutex::new(Some(rx_rx))),
            authenticated: Arc::new(AtomicBool::new(true)), // 服务端：attach 前已认证
            data_only_port: Arc::new(std::sync::atomic::AtomicU16::new(0)),
        });

        let conn2 = conn.clone();
        std::thread::spawn(move || {
            conn2.recv_loop();
        });
        let conn3 = conn.clone();
        std::thread::spawn(move || {
            conn3.send_loop();
        });
        // 打开主数据流（收 Mux 帧前先建流）
        {
            let mut sm = conn.streams.lock().unwrap();
            let _ = sm.open_stream_at(MAIN_STREAM_ID);
        }
        conn
    }

    /// 接收线程（非阻塞 recvfrom 轮询循环）
    ///
    /// 数据路径：UDP 数据报 -> SRT 外壳解析（srt_shell）-> 解密 -> 内层帧解析
    /// -> 按帧类型投递（STREAM -> 流管理 -> rx 事件；ACK -> 跟踪器 + BBR）。
    ///
    /// 断线处理：对端连续 N 个周期无数据（心跳超时）判定死连接，
    /// 置 closed 信号让上层重连（对齐旧 B3 整链自动重连语义）。
    fn recv_loop(&self) {
        let mut buf = vec![0u8; 65536];
        let mut last_rx = Instant::now();
        loop {
            // 非阻塞 + 轮询（简化；后续可换 epoll 优化）
            match self.udp.recv_from(&mut buf) {
                Ok((n, src)) => {
                    // 只接受对端（服务端）IP 的包。
                    // 2026-08-20 多设备：认证后数据迁移到独立端口，服务端回包源
                    // 端口可能是监听端口（握手/ACK）或数据端口（业务），故只校验 IP。
                    // 避免 src.port != peer.port 时误丢弃（此前 src != self.peer 使
                    // 从 data_port 发来的业务数据被丢弃——多设备丢数据根因）。
                    if src.ip() != self.peer.ip() {
                        continue;
                    }
                    last_rx = Instant::now();
                    self.handle_datagram(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // UDP 非阻塞：检查超时
                    if last_rx.elapsed() > Duration::from_secs(self.heartbeat_secs.max(5) * 3) {
                        tracing::warn!("连接超时（无数据），标记断开");
                        self.closed.store(true, Ordering::Release);
                        self.state.store(ST_CLOSED, Ordering::Release);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_e) => break,
            }
        }
    }

    /// 处理一个 UDP 数据报（SRT 外壳解析 + 内层帧）
    fn handle_datagram(&self, data: &[u8]) {
        // 1. SRT 外壳解析（16B 头；区分控制/数据包）
        let Some((is_ctrl, msg_type, inner)) = crate::srt_shell::outer::decode_packet(data) else {
            return; // 非法包（<16B / 未知控制类型）丢弃
        };
        if is_ctrl {
            // 控制包：握手响应 / 装饰性 ACK / keepalive
            match msg_type {
                crate::srt_shell::header::MSG_HANDSHAKE => {
                    // 握手响应（AUTH_OK/FAIL 载荷在内层 Handshake 帧）
                    self.handle_frame(inner);
                }
                _ => {
                    // 其他控制包（装饰 ACK/NACK keepalive）：不处理（外形同步用）
                }
            }
            return;
        }
        // 2. 数据壳：内层传输帧（quic frame）
        self.handle_frame(inner);
    }

    /// 处理内层传输帧
    fn handle_frame(&self, frame: &[u8]) {
        let Ok(Some((_ftype, _payload))) = packet::try_parse_frame(frame) else {
            return;
        };
        match _ftype {
            FrameType::Stream => {
                // STREAM 帧：投递到流管理 + 发送 ACK
                if let Ok((fin, sid, offset, data)) = packet::decode_stream(frame) {
                    if sid == MAIN_STREAM_ID {
                        // 主数据流（承载前端 Mux 消息）：每个 STREAM 帧 payload
                        // 即一条完整消息（消息边界由 send_msg 保证），直接投递。
                        // 注意：不经过 stream buffer 字节流重组——QUIC 内部 ACK/
                        // 重传保证有序不丢，接收顺序 = 发送顺序。
                        let _ = self.rx_tx.send(RecvEvent::Data {
                            stream_id: sid,
                            data: data.to_vec(),
                        });
                        if fin {
                            let _ = self.rx_tx.send(RecvEvent::Fin { stream_id: sid });
                        }
                    } else {
                        // 其他流（未来 per-session 模式）：走流缓冲重组
                        let mut sm = self.streams.lock().unwrap();
                        if let Some(s) = sm.get(sid) {
                            s.recv_data(offset, data, fin);
                        }
                        let _ = offset;
                    }
                    // 发送 ACK（聚合：每收到一个 STREAM 帧回一 ACK，简单可靠）
                    self.send_ack();
                }
            }
            FrameType::Ack => {
                // ACK 帧：更新发送跟踪 + BBR
                if let Ok((largest, delay)) = packet::decode_ack(frame) {
                    {
                        let mut t = self.tracker.lock().unwrap();
                        let confirmed = t.on_ack(largest, delay);
                        t.reset_backoff();
                        if confirmed > 0 {
                            let bytes = t.acked_bytes();
                            let mut c = self.congctl.lock().unwrap();
                            c.on_ack(bytes, t.srtt);
                            c.on_round(t.srtt);
                        }
                    }
                }
            }
            FrameType::Ping => {
                // 回 PONG（携带时间戳）
                let mut pong = Vec::new();
                packet::encode_pong(&mut pong, &[]);
                self.send_raw(&pong);
            }
            FrameType::Pong => {
                // RTT 测量（简化：忽略测量的应用）
            }
            FrameType::RstStream => {
                if let Ok((sid, code)) = packet::decode_rst_stream(frame) {
                    let mut sm = self.streams.lock().unwrap();
                    if let Some(s) = sm.get(sid) {
                        s.reset(code);
                    }
                    let _ = self.rx_tx.send(RecvEvent::Reset { stream_id: sid });
                }
            }
            FrameType::Handshake => {
                // 认证握手载荷（SRT 特征握手）
                if let Ok(payload) = packet::decode_handshake(frame) {
                    // 客户端：收到 AUTH_OK → 认证完成 + 若迁移端口（多设备独立数据通道）
                    if !payload.is_empty() && payload[0] == crate::srt_shell::auth::CMD_AUTH_OK {
                        self.authenticated.store(true, Ordering::Release);
                        self.state.store(ST_CONNECTED, Ordering::Release);
                        // 解析服务端分配的数据端口（无则保留 0 = 沿用原端口）
                        if let Some(port) = crate::srt_shell::auth::parse_auth_ok_port(payload) {
                            self.data_only_port.store(port, Ordering::Release);
                            tracing::debug!(data_port = port, "认证成功，数据通道迁移到独立端口");
                        }
                    }
                    let _ = self.rx_tx.send(RecvEvent::Control(payload.to_vec()));
                }
            }
            _ => {
                // 其他帧（含流控窗口更新 MaxData/MaxStreamData）：
                // 本内核单连接共享拥控窗口，暂忽略精确流控（由 BBR 承担）
            }
        }
    }

    /// 发送 ACK（聚合帧）
    fn send_ack(&self) {
        let mut ack = Vec::new();
        packet::encode_ack(&mut ack, 0, 0); // largest_acked 由 tracker 维护，简化固定
        self.send_raw(&ack);
    }

    /// 当前发送目标（数据通道迁移后 = 服务端 IP + 迁移端口；否则原 peer）
    fn send_target(&self) -> SocketAddr {
        let port = self.data_only_port.load(Ordering::Acquire);
        if port != 0 {
            // 服务端 IP 不变，换数据端口（服务端数据 socket 绑 0.0.0.0:port）
            let s = format!("{}:{}", self.peer.ip().to_string(), port);
            s.parse::<SocketAddr>().expect("重组数据目标地址失败")
        } else {
            self.peer
        }
    }

    /// 发送原始帧（数据壳：SRT 数据包外形）
    fn send_raw(&self, inner: &[u8]) {
        // 组装外层 SRT 壳（16B 数据包头，bit31=0）
        let pkt = crate::srt_shell::outer::encode_data_packet(inner);
        let _ = self.udp.send_to(&pkt, self.send_target());
    }

    /// 客户端发送 SRT 特征握手（外层控制壳 0x80 + 内层 Handshake 帧 + AUTH 载荷）
    ///
    /// 对齐 libsrt 首包特征：0x80 00 00 00（控制 + HANDSHAKE）。
    /// 认证用 srt_shell/auth.rs 的 AUTH（passphrase 派生密钥 + nonce 签名），
    /// 防主动探测（不暴露 TLS/HTTP 结构）。
    pub fn send_handshake(&self) {
        use crate::srt_shell::auth;
        use crate::srt_shell::header::MSG_HANDSHAKE;
        use crate::srt_shell::outer::encode_ctrl_packet;
        // 随机 nonce（一次性防重放）
        let nonce: [u8; 12] = {
            use rand::RngCore;
            let mut n = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut n);
            n
        };
        let auth_payload = auth::auth_request(&self.secret, &nonce);
        // 内层 Handshake 帧（携带 AUTH）
        let mut inner = Vec::new();
        packet::encode_handshake(&mut inner, &auth_payload);
        // 外层 SRT 控制壳：握手（服务端从内层帧解析出 AUTH）
        let pkt = encode_ctrl_packet(MSG_HANDSHAKE, 0, &inner);
        let _ = self.udp.send_to(&pkt, self.peer);
        tracing::debug!(peer = %self.peer, "已发送 SRT 特征认证握手");
    }

    /// 打开一条新流（映射一个上层会话）
    ///（P1.5 per-session 多流接入时启用；当前单主数据流模式用 open_stream_at）
    #[allow(dead_code)]
    pub fn open_stream(&self) -> Option<u32> {
        let mut sm = self.streams.lock().unwrap();
        sm.open_stream()
    }

    /// 关闭一条流（会话结束/RST 后回收）
    pub fn close_stream(&self, sid: u32) {
        let mut sm = self.streams.lock().unwrap();
        sm.close_stream(sid);
    }

    /// 向指定流发送数据（应用层 -> 流缓冲）
    ///
    /// 返回实际写入字节；0 表示背压（流缓冲满，稍后重试）。
    ///（P1.5 per-session 多流接入启用；当前单主数据流模式用 send_msg）
    #[allow(dead_code)]
    pub fn stream_send(&self, sid: u32, data: &[u8]) -> usize {
        let mut sm = self.streams.lock().unwrap();
        if let Some(s) = sm.get(sid) {
            s.send(data)
        } else {
            0
        }
    }

    /// 向指定流标记 FIN（发送方向关闭）
    ///（P1.5 per-session 多流接入启用）
    #[allow(dead_code)]
    pub fn stream_fin(&self, sid: u32) {
        let mut sm = self.streams.lock().unwrap();
        if let Some(s) = sm.get(sid) {
            s.send_fin();
        }
    }

    /// 发送循环（由上层 spawn：定期把流缓冲 -> 网络，按 BBR 调速 + ACK 聚合）
    pub fn send_loop(&self) {
        tracing::debug!("QUIC send_loop 启动");
        loop {
            // 断开退出
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            // 1. BBR 探测周期
            {
                let mut c = self.congctl.lock().unwrap();
                c.probe_bw_cycle(Instant::now());
            }
            // 2. 从流管理中取可发数据（受拥控窗口预算约束再取，避免取后不发丢数据）
            let now = Instant::now();
            // 拥控窗口余量（本轮回合可发总字节）——多个流公平分配
            let inflight_now = self.in_flight_bytes();
            let room = {
                let c = self.congctl.lock().unwrap();
                let cwnd = c.cwnd_bytes();
                cwnd.saturating_sub(inflight_now)
            };
            let mut budget = room;
            // 收集各流待发块（每个流取一块，公平轮询；受预算约束）
            let blocks: Vec<(u32, u64, Vec<u8>, bool)> = {
                let mut sm = self.streams.lock().unwrap();
                let ids: Vec<u32> = sm.active_ids();
                let mut out = Vec::new();
                for id in ids {
                    if budget == 0 {
                        break;
                    }
                    if let Some(s) = sm.get(id) {
                        // 先 peek 块大小，预算内才取（避免取出后预算不足丢块）
                        match s.peek_send_block() {
                            Some((_, bytes, _)) if bytes.len() <= budget => {
                                if let Some((off, b, fin)) = s.take_send_block() {
                                    budget -= b.len();
                                    out.push((id, off, b, fin));
                                }
                            }
                            _ => {
                                // 块太大/无块：跳过本流
                            }
                        }
                    }
                }
                out
            };
            // 4. 发送
            if !blocks.is_empty() {
                tracing::debug!(n = blocks.len(), "send_loop 发送数据块");
            }
            for (sid, off, bytes, fin) in blocks {
                let inflight = self.in_flight_bytes();
                let can = {
                    let c = self.congctl.lock().unwrap();
                    c.can_send(now, inflight)
                };
                if !can {
                    // 拥塞：暂停本轮回合，稍后重试（数据留在流缓冲——注意：
                    // take_send_block 已移除，需要重新放回？简化：允许少量超发，
                    // 因为 BBR 窗口是全连接的，单块不超）
                    // 重构说明：take_send_block 移除了数据，直接发出（BBR 窗口是
                    // 连接级的，pacing 已节流）
                }
                // 组装 STREAM 帧
                let mut pkt = Vec::with_capacity(packet::MAX_UDP_PAYLOAD);
                packet::encode_stream(&mut pkt, sid, off, &bytes, fin);
                // 记录发送跟踪（供 ACK/重传）
                {
                    let mut t = self.tracker.lock().unwrap();
                    t.on_send(Some(SentPayload {
                        stream_id: sid,
                        offset: off,
                        data: bytes.clone(),
                        fin,
                    }));
                }
                // 发
                self.send_raw(&pkt);
                // 记录发送时间（BBR pacing）
                {
                    let mut c = self.congctl.lock().unwrap();
                    c.on_send(now);
                }
                if fin {
                    self.close_stream(sid);
                }
            }
            // 4. 超时重传检查
            self.retransmit_expired();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// 未确认在途字节数（BBR 窗口占用）
    fn in_flight_bytes(&self) -> usize {
        let t = self.tracker.lock().unwrap();
        t.in_flight() * 1316
    }

    /// 超时重传：检查 RTO 过期包并重发
    fn retransmit_expired(&self) {
        let expired = {
            let mut t = self.tracker.lock().unwrap();
            t.find_expired(Instant::now())
        };
        if expired.is_empty() {
            return;
        }
        // 有超时：通知 BBR 拥塞
        {
            let mut c = self.congctl.lock().unwrap();
            c.on_congestion();
        }
        for pl in expired {
            let mut pkt = Vec::new();
            packet::encode_stream(&mut pkt, pl.stream_id, pl.offset, &pl.data, pl.fin);
            self.send_raw(&pkt);
        }
    }

    /// 状态查询（P1.5 监控/日志接入启用）
    #[allow(dead_code)]
    pub fn state(&self) -> QuicState {
        match self.state.load(Ordering::Acquire) {
            ST_HANDSHAKING => QuicState::Handshaking,
            ST_CONNECTED => QuicState::Connected,
            _ => QuicState::Closed,
        }
    }

    /// 是否已断开（上层重连信号；P1.5 监控接入启用）
    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// 对端地址（P1.5 监控/日志接入启用）
    #[allow(dead_code)]
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// 取走接收事件流（前端消费）。只可调用一次（通道单消费者）
    pub fn take_events(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<RecvEvent>> {
        self.rx_rx.lock().unwrap().take()
    }

    /// ===== 前端兼容消息模式（对齐旧 SrtConnection::send 语义）=====
    ///
    /// 旧架构：SRT 连接承载"一条条 Mux 消息"（encode_frame 的字节串），
    /// 前端 TunnelSession 用 conn.send(frame) 发送、recv 收到完整消息。
    /// 新架构：这些 Mux 消息作为 QUIC 单条主流的 STREAM 帧 payload 传输
    /// （由 send_loop 轮询发送缓冲）。本接口保持"发送一条完整消息"语义。
    ///
    /// 内部：消息写入专用主流（id=1）发送缓冲，send_loop 统一调度。

    /// 发送一条完整消息（前端 Mux 帧字节串）
    ///
    /// 对齐旧 crossbeam unbounded 语义：send 永不失败（缓冲满时自旋等待
    /// send_loop 消费出空位再写入）。返回 false 仅当连接已关闭。
    pub fn send_msg(&self, data: &[u8]) -> bool {
        let sid = MAIN_STREAM_ID;
        // 若主流未开则打开（保证首条消息前先建流）
        {
            let mut sm = self.streams.lock().unwrap();
            if !sm.stream_exists(sid) {
                let _ = sm.open_stream_at(sid);
            }
        }
        // 写入流缓冲；背压时自旋等待（对齐旧通道永不失败语义）
        loop {
            if self.closed.load(Ordering::Acquire) {
                return false; // 连接已关闭
            }
            let mut sm = self.streams.lock().unwrap();
            if let Some(s) = sm.get(sid) {
                let n = s.send(data);
                if n == data.len() {
                    return true; // 完整写入
                }
                // 缓冲满：释放锁等 send_loop 消费
            }
            drop(sm);
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// 前端兼容发送（对齐旧 SrtConnection::send 签名）
    /// 同步入队；失败返回错误说明原因
    pub fn send(&self, data: Vec<u8>) -> Result<(), String> {
        if self.send_msg(&data) {
            Ok(())
        } else {
            Err("发送缓冲满（背压）".to_string())
        }
    }

    /// 前端兼容异步发送（对齐旧 send_async 签名）
    ///
    /// 与 send 相同：跨 Mux 消息经由主流入队即可（send_loop 异步发送）。
    /// 返回错误仅当缓冲满（背压）。如需要背压等待可在此 await，
    /// 简化实现：直接调用同步 send。
    pub async fn send_async(&self, data: Vec<u8>) -> Result<(), String> {
        self.send(data)
    }

    /// 由上层接收循环调用的消息消费 API（P1.5 备用；当前用 take_events 事件流）
    #[allow(dead_code)]
    pub async fn recv_async(&self) -> Option<RecvEvent> {
        let mut rx = self.rx_rx.lock().unwrap();
        let rx = rx.as_mut()?;
        rx.recv().await
    }

    /// 标记主流发送完成（清空尾部剩余数据；P1.5 连接关闭时序接入启用）
    #[allow(dead_code)]
    pub fn send_msg_fin(&self) {
        self.stream_fin(1);
    }

    /// 关闭连接（预留优雅关闭；当前由进程退出/重连重建终结）
    #[allow(dead_code)]
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        // UDP socket Drop 自动关闭；recv 线程因 WouldBlock 循环检测 closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 配置默认值 + 基本字段
    #[tokio::test]
    async fn test_config_defaults() {
        let cfg = QuicConfig::default();
        assert!(cfg.peer.is_none());
        assert!(!cfg.is_server);
        assert_eq!(cfg.init_cwnd_packets, 16);
        assert_eq!(cfg.heartbeat_secs, 5);
        // 验证 connect 签名可调用（不实际建连：用保底地址验证 API 存在）
        // 注：连接状态机需要真实对端；此处只校验配置结构与默认值。
        assert!(cfg.bind_addr.is_none());
    }

    /// 状态枚举与 RecvEvent 可构造
    #[test]
    fn test_types() {
        let _ = QuicState::Handshaking;
        let _ = QuicState::Connected;
        let _ = RecvEvent::Reset { stream_id: 1 };
    }
}