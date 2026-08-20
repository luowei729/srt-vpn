//! quic/connection.rs - 自研 QUIC 语义连接 v2（核心状态机）
//!
//! 2026-08-20 v2 完整重写（传输层质量重构）：
//! v1 病灶：① 确认键用字节偏移（接收方拿不到发送方包号，ACK 语义三轮补丁
//! 对不齐）② 一帧处理加锁 3-4 次（streams/tracker/congctl 各一把）③
//! take_send_block 取出即删 + tracker 存副本（内存双份）④ pacing 检查后
//! 照发不误 ⑤ 真假两套 ACK（内层帧 ACK + 外壳装饰 ACK）互相打架。
//!
//! v2 架构（回归 RFC9000 标准语义）：
//! - **包号驱动**：每个数据包的包号放 SRT 外壳 SEQ 字段（真 SRT 同款），
//!   接收方按包号确认，ACK 区间即丢包证据，语义天然闭环
//! - **单状态锁**：streams + send tracker + recv tracker + CUBIC 一把
//!   Mutex（`ConnState`），锁内决策锁外发送（sendto 原子）
//! - **周期 ACK**：控制线程每 ~10ms 发一次 ACK（真 SRT 的 ACK 节奏，
//!   拟真 + 聚合双重收益），ACK 丢了下周期补发，不需要可靠
//! - **重传即重发原帧**：SendTracker 存原始帧字节，快速重传/RTO 都直接
//!   重发（保留原包号，SRT 语义；幂等由接收方 offset 去重保证）
//! - **装饰 ACK 合一**：周期 ACK 本身就是 0x80 02 控制壳（SRT ACK 外形），
//!   不再单独发装饰包
//!
//! 线程模型：接收线程（recv 循环）+ 发送线程（send 循环）+ 事件通道（上层）。
//! 外部接口与 v1 完全兼容（connect/attach_peer/take_events/send/RecvEvent），
//! 前端（client/server/pool/tunnel）零改动。

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::quic::ack::{now_micros, RecvTracker, SendTracker};
use crate::quic::congctl::CubicSender;
use crate::quic::packet::{self, FrameType};
use crate::quic::stream::StreamManager;

/// 接收事件（上层消费；与 v1 兼容）
#[derive(Debug)]
pub enum RecvEvent {
    /// 应用数据（字节；单主流模式，stream_id 未来 per-session 接入启用）
    Data { #[allow(dead_code)] stream_id: u32, data: Vec<u8> },
    /// 流 FIN（对端发送方向关闭）
    Fin { stream_id: u32 },
    /// 流 RST
    Reset { stream_id: u32 },
    /// 连接级事件（握手响应/心跳等）
    Control(Vec<u8>),
}

/// 连接配置（与 v1 兼容）
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// 对端地址（客户端必填；服务端 attach_peer 指定）
    pub peer: Option<SocketAddr>,
    /// 预留（v1 兼容）
    #[allow(dead_code)]
    pub is_server: bool,
    #[allow(dead_code)]
    pub bind_addr: Option<SocketAddr>,
    /// 载荷加密密钥（passphrase 派生）
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

/// 主数据流 ID（前端 Mux 消息单流模式）
const MAIN_STREAM_ID: u32 = 1;

/// ACK 发送周期（2026-08-20 性能优化，学 quic-go）：
/// 主要 ACK 路径是"每 2 包立即发"（ack_queued），这个是兜底定时器
/// （25ms），仅在有零星 ack-eliciting 包不到 2 个时保证不遗漏 ACK。
/// RFC9000 标准 max_ack_delay = 25ms。
const ACK_INTERVAL: Duration = Duration::from_millis(25);

/// 连接共享状态（单锁保护：发送/接收/拥控全部状态）
struct ConnState {
    /// 发送跟踪（未确认表 + RTO）
    tracker: SendTracker,
    /// 接收跟踪（已收集合 + ACK 区间生成）
    recv: RecvTracker,
    /// 流管理（发送缓冲 + 接收重组）
    streams: StreamManager,
    /// 拥塞控制（CUBIC + Hybrid Slow Start + pacer，学 quic-go）
    cong: CubicSender,
    /// 上次 ACK 发送时刻（周期 ACK 节流）
    last_ack_at: Instant,
    /// 最近一次数据接收时刻（断线检测）
    last_recv_at: Instant,
}

/// 自研 QUIC 语义连接 v2
///
/// 2026-08-20 v2 重构（学 quic-go 事件驱动）：
/// 发送线程不再轮询 sleep，改用 Condvar 事件唤醒：
/// - send_msg 入队 -> notify_send
/// - on_ack 释放预算 -> notify_send
/// - on_pong RTT 更新 -> notify_send
/// send_loop 收到通知立即取块发送，无数据时 condvar wait（零 CPU）。
pub struct QuicConnection {
    /// UDP socket（收发共用）
    udp: Arc<UdpSocket>,
    /// 对端地址
    peer: SocketAddr,
    /// 共享状态（单锁）
    state: Mutex<ConnState>,
    /// 发送唤醒信号（事件驱动，学 quic-go scheduleSending channel）
    /// send_msg/on_ack/on_pong 调 notify_send 唤醒 send_loop，
    /// send_loop 无数据时 wait（零 CPU 轮询）
    send_trigger: Mutex<()>,
    send_cvar: Condvar,
    /// 断开信号（上层重连）
    closed: Arc<AtomicBool>,
    /// 事件通道（上层 take_events 消费）
    rx_tx: tokio::sync::mpsc::UnboundedSender<RecvEvent>,
    rx_rx: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<RecvEvent>>>,
    /// 加密上下文（AES-128-CTR；2026-08-20 性能优化替换旧 SHA256 密钥流）
    #[cfg_attr(feature = "no-crypto", allow(unused))]
    cipher: crate::quic::crypto::PacketCipher,
    /// 原始密钥（握手认证仍用，auth_request 需要 [u8;16]）
    secret: [u8; 16],
    /// 认证完成标志（客户端等 AUTH_OK）
    authenticated: Arc<AtomicBool>,
    /// 迁移数据端口（0 = 未迁移）
    data_only_port: Arc<AtomicU16>,
    /// 心跳间隔
    heartbeat_secs: u64,
    /// 下一包号（发送方全局递增；与外壳 SEQ 对齐）
    next_pkt_num: AtomicU64,
    /// 上次心跳 PING 时刻
    last_ping: Mutex<Instant>,
}

/// 尝试调大 UDP socket 收发缓冲（高吞吐必需）
///
/// 内核默认 rmem/wmem 仅 208KB，高吞吐下接收缓冲溢出丢包（AGENTS.md
/// 2026-08-20 05:30 教训）。尝试 4MB，被 rmem_max 钳制则尽力而为。
pub fn enlarge_socket_buffers(sock: &UdpSocket) {
    const TARGET: i32 = 4 * 1024 * 1024;
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &TARGET as *const _ as *const libc::c_void, std::mem::size_of::<i32>() as u32);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &TARGET as *const _ as *const libc::c_void, std::mem::size_of::<i32>() as u32);
    }
}

impl QuicConnection {
    /// 客户端入口：connect 对端 + SRT 特征握手 + 等认证完成
    pub async fn connect(cfg: &QuicConfig) -> io::Result<Arc<Self>> {
        let peer = cfg.peer.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "客户端需 peer"))?;
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_nonblocking(true)?;
        enlarge_socket_buffers(&sock);

        let (rx_tx, rx_rx) = tokio::sync::mpsc::unbounded_channel::<RecvEvent>();
        let conn = Arc::new(Self {
            udp: Arc::new(sock),
            peer,
            state: Mutex::new(ConnState {
                tracker: SendTracker::new(),
                recv: RecvTracker::new(),
                streams: StreamManager::new(),
                cong: CubicSender::new(),
                last_ack_at: Instant::now(),
                last_recv_at: Instant::now(),
            }),
            send_trigger: Mutex::new(()),
            send_cvar: Condvar::new(),
            closed: Arc::new(AtomicBool::new(false)),
            cipher: crate::quic::crypto::PacketCipher::new(cfg.secret),
            secret: cfg.secret,
            rx_tx,
            rx_rx: Mutex::new(Some(rx_rx)),
            authenticated: Arc::new(AtomicBool::new(false)),
            data_only_port: Arc::new(AtomicU16::new(0)),
            heartbeat_secs: cfg.heartbeat_secs.max(5),
            next_pkt_num: AtomicU64::new(0),
            last_ping: Mutex::new(Instant::now()),
        });
        // 打开主数据流
        conn.state.lock().unwrap().streams.open(MAIN_STREAM_ID);

        // 收发线程
        let c2 = conn.clone();
        std::thread::spawn(move || c2.recv_loop());
        let c3 = conn.clone();
        std::thread::spawn(move || c3.send_loop());

        // 发送 SRT 特征握手（AUTH），等 AUTH_OK（8s 超时）
        conn.send_handshake()?;
        let deadline = Instant::now() + Duration::from_secs(8);
        while !conn.authenticated.load(Ordering::Acquire) {
            if Instant::now() > deadline {
                conn.closed.store(true, Ordering::Release);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "认证超时"));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(conn)
    }

    /// 服务端入口：attach 到已认证客户端的共享监听 socket
    ///
    /// 2026-08-20 单端口修复：不再 spawn recv_loop（避免多连接 recv_from 竞争抢读）。
    /// 接收由 QuicListener 的单一接收线程统一做，按 src 地址分发到各连接的
    /// handle_datagram。本方法只 spawn send_loop（发送仍由连接自身管理）。
    pub fn attach_peer(udp: Arc<UdpSocket>, peer: SocketAddr, secret: [u8; 16], heartbeat_secs: u64) -> Arc<Self> {
        let (rx_tx, rx_rx) = tokio::sync::mpsc::unbounded_channel::<RecvEvent>();
        let conn = Arc::new(Self {
            udp,
            peer,
            state: Mutex::new(ConnState {
                tracker: SendTracker::new(),
                recv: RecvTracker::new(),
                streams: StreamManager::new(),
                cong: CubicSender::new(),
                last_ack_at: Instant::now(),
                last_recv_at: Instant::now(),
            }),
            send_trigger: Mutex::new(()),
            send_cvar: Condvar::new(),
            closed: Arc::new(AtomicBool::new(false)),
            cipher: crate::quic::crypto::PacketCipher::new(secret),
            secret,
            rx_tx,
            rx_rx: Mutex::new(Some(rx_rx)),
            authenticated: Arc::new(AtomicBool::new(true)),
            data_only_port: Arc::new(AtomicU16::new(0)),
            heartbeat_secs: heartbeat_secs.max(5),
            next_pkt_num: AtomicU64::new(0),
            last_ping: Mutex::new(Instant::now()),
        });
        conn.state.lock().unwrap().streams.open(MAIN_STREAM_ID);

        // 只 spawn send_loop（接收由 listener 统一分发，不在此 spawn recv_loop）
        let c3 = conn.clone();
        std::thread::spawn(move || c3.send_loop());
        conn
    }

    // ========================================================================
    // 接收路径：UDP -> 外壳解析 -> 解密 -> 帧分发
    // ========================================================================

    /// 接收线程（仅客户端用；服务端由 QuicListener 统一 recv_from 分发）
    ///
    /// 客户端是独立 socket 无竞争，可自行 recv_from。
    /// 服务端共享监听 socket，多连接若各自 recv_from 会抢读丢包
    ///（连接池第 2~4 条连接认证超时的根因），改由 listener 单线程分发。
    fn recv_loop(&self) {
        let mut buf = vec![0u8; 65536];
        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            match self.udp.recv_from(&mut buf) {
                Ok((n, src)) => {
                    // 只处理对端 IP 的包（端口可能因数据通道迁移变化）
                    if src.ip() != self.peer.ip() {
                        continue;
                    }
                    self.handle_datagram(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // 空闲：sleep 50µs 回轮。
                    // 2026-08-20 性能优化：500µs → 50µs。上传场景服务端 recv_loop
                    // 在两批数据包之间 WouldBlock，500µs sleep 成为每批 500µs 延迟
                    // 瓶颈（上传 24 vs 下载 150 MB/s 的主因）。50µs 与 send_loop
                    // EAGAIN 重试对齐，CPU 开销可忽略（空闲态才会到此分支）。
                    std::thread::sleep(Duration::from_micros(50));
                }
                Err(_) => break,
            }
        }
    }

    /// 处理一个 UDP 数据报（外壳解析 + 解密 + 帧分发）
    ///
    /// pub：服务端由 QuicListener 接收线程调用（统一 recv_from 后按 src 分发）。
    /// 客户端由自身 recv_loop 调用。
    ///
    /// 包号记账（2026-08-20 v2 关键修复）：**所有数据壳包**（STREAM/PING/
    /// PONG/RST）消耗包号序列，必须全部记入 received 集合。旧版只记
    /// STREAM 帧--PING/PONG 的包号成黑洞，ACK 区间把黑洞当 gap 报给
    /// 发送方（误判丢包重传），而真实丢包反而淹没在噪声里。
    pub fn handle_datagram(&self, data: &[u8]) {
        let Some((pkt_num, frame)) = self.decode_wire(data) else {
            return; // 非法包（<16B / 未知控制类型 / 解密失败）静默丢弃
        };
        // 数据壳包统一记账（控制壳包号无意义跳过）
        if !matches!(frame, WireFrame::Ack(..) | WireFrame::Handshake(..)) {
            let mut st = self.state.lock().unwrap();
            st.recv.on_recv(pkt_num);
            st.last_recv_at = Instant::now();
        }
        match frame {
            WireFrame::Data(inner) => self.on_stream_frame(pkt_num, &inner),
            WireFrame::Ack(largest, delay, ranges) => self.on_ack_frame(largest, delay, &ranges),
            WireFrame::Ping(payload) => self.on_ping(&payload),
            WireFrame::Pong(payload) => self.on_pong(&payload),
            WireFrame::Rst(sid, code) => self.on_rst(sid, code),
            WireFrame::Handshake(payload) => self.on_handshake(&payload),
        }
    }

    /// 线协议解码：SRT 外壳 + 加密 + 帧首字节分流
    fn decode_wire(&self, data: &[u8]) -> Option<(u64, WireFrame)> {
        let (pkt_num, is_ctrl, msg_type, inner) = crate::srt_shell::outer::decode_packet_v2(data)?;
        if is_ctrl {
            // 控制壳：ACK（明文，SRT 同款）或握手（明文承载 AUTH）
            match msg_type {
                crate::srt_shell::header::MSG_ACK => {
                    let (largest, delay, ranges) = packet::decode_ack_ranges(inner).ok()?;
                    Some((pkt_num, WireFrame::Ack(largest, delay, ranges)))
                }
                crate::srt_shell::header::MSG_HANDSHAKE => {
                    let payload = packet::decode_handshake(inner).ok()?;
                    Some((pkt_num, WireFrame::Handshake(payload.to_vec())))
                }
                _ => None,
            }
        } else {
            // 数据壳：数据面加密分流
            #[cfg(not(feature = "no-crypto"))]
            let plain = self.cipher.decrypt_packet(inner)?;
            #[cfg(feature = "no-crypto")]
            let plain = inner.to_vec();
            let first = *plain.first()?;
            match FrameType::from_byte(first) {
                Some(FrameType::Stream) => {
                    Some((pkt_num, WireFrame::Data(plain)))
                }
                Some(FrameType::Ping) => {
                    let p = packet::decode_ping(&plain).ok()?;
                    Some((pkt_num, WireFrame::Ping(p.to_vec())))
                }
                Some(FrameType::Pong) => {
                    let p = packet::decode_pong(&plain).ok()?;
                    Some((pkt_num, WireFrame::Pong(p.to_vec())))
                }
                Some(FrameType::RstStream) => {
                    let (sid, code) = packet::decode_rst_stream(&plain).ok()?;
                    Some((pkt_num, WireFrame::Rst(sid, code)))
                }
                _ => None,
            }
        }
    }

    /// STREAM 帧处理：包号记账（handle_datagram 已统一记录）+ 流重组 + 事件投递
    fn on_stream_frame(&self, _pkt_num: u64, frame: &[u8]) {
        let Ok((fin, sid, offset, data)) = packet::decode_stream(frame) else {
            return;
        };
        let mut events: Vec<RecvEvent> = Vec::new();
        {
            let mut st = self.state.lock().unwrap();
            // 包号记账已上移到 handle_datagram（所有数据壳包统一记录）
            if !st.streams.exists(sid) {
                st.streams.open(sid);
            }
            if let Some(s) = st.streams.get(sid) {
                s.recv_data(offset, data, fin);
                // 取已重组数据块投递上层（**保持块边界**：每块 = 一条
                // 应用消息/Mux 帧，块边界由发送侧 send_msg 单帧入队保证）
                if s.has_delivered() {
                    for block in s.take_delivered_blocks() {
                        events.push(RecvEvent::Data { stream_id: sid, data: block });
                    }
                }
                if s.is_finished() {
                    events.push(RecvEvent::Fin { stream_id: sid });
                    // ⚠️ 不能 remove 流！发送方流 offset 单调递增不重置，
                    // 若删了重开（delivered_offset 归零）则后续 offset 对
                    // 不上永远卡 unordered（多会话下载全卡死根因）。
                    // 流上下文由连接生命周期管理（单主流模式常驻）。
                }
            }
        }
        for e in events {
            let _ = self.rx_tx.send(e);
        }
    }

    /// ACK 帧处理：确认 + 快速重传 + CUBIC + 唤醒发送
    ///
    /// 2026-08-20 重构（学 quic-go 事件驱动 + CUBIC）：
    /// 收到 ACK 后通知 send_loop 继续发（释放了 cwnd 预算），
    /// 替代旧的"等下次轮询"延迟。
    fn on_ack_frame(&self, largest: u64, _delay: u32, ranges: &[(u64, u64)]) {
        // 快速重传（锁内新包号记账，锁外加密发送）
        let retrans: Vec<(u64, Vec<u8>)> = {
            let mut st = self.state.lock().unwrap();
            // 先取 ACK 前的 inflight（quic-go prior_in_flight 是 ACK 前的值，
            // ACK 处理后会清空 sent map 导致 inflight=0 -> is_cwnd_limited
            // 永远 false -> cwnd 永不增长的根因）
            let prior_inflight = st.tracker.in_flight_bytes() as u64;
            let (confirmed, lost) = st.tracker.on_ack(largest, ranges, None);
            if confirmed > 0 {
                // CUBIC OnPacketAcked（quic-go 同款：prior_in_flight + acked_bytes
                // + event_time + latest_rtt + min_rtt）
                let srtt = st.tracker.srtt();
                let min_rtt = srtt; // 简化：min_rtt 用 srtt 近似
                st.cong.on_packet_acked(largest, confirmed as u64 * crate::quic::ack::MSS as u64, prior_inflight, Instant::now(), srtt, min_rtt);
            }
            lost.into_iter()
                .map(|frame| {
                    let pkt_num = self.next_pkt_num.fetch_add(1, Ordering::Relaxed);
                    st.tracker.on_send(pkt_num, frame.clone(), true);
                    (pkt_num, frame)
                })
                .collect()
        };
        for (pkt_num, frame) in retrans {
            self.send_frame_encrypted(&frame, pkt_num);
        }
        // 事件驱动：ACK 释放了 cwnd 预算，唤醒发送线程继续发
        self.notify_send();
    }

    /// PING：回 PONG（回显载荷；新包号）
    fn on_ping(&self, payload: &[u8]) {
        let mut pong = Vec::with_capacity(1 + payload.len());
        packet::encode_pong(&mut pong, payload);
        let pkt_num = self.next_pkt_num.fetch_add(1, Ordering::Relaxed);
        self.send_frame_encrypted(&pong, pkt_num);
    }

    /// PONG：RTT 采样 + 唤醒发送（pacer rate 可能更新）
    fn on_pong(&self, payload: &[u8]) {
        if payload.len() == 8 {
            let sent_us = u64::from_be_bytes(payload.try_into().unwrap());
            let now_us = now_micros();
            if now_us > sent_us {
                let mut st = self.state.lock().unwrap();
                st.last_recv_at = Instant::now();
                st.tracker.on_rtt_sample(Duration::from_micros(now_us - sent_us));
            }
        }
        // RTT 更新可能改变 min_rtt，pacer rate 随之变，唤醒重算
        self.notify_send();
    }

    /// RST 流重置
    fn on_rst(&self, sid: u32, _code: u32) {
        let mut st = self.state.lock().unwrap();
        st.streams.remove(sid);
        drop(st);
        let _ = self.rx_tx.send(RecvEvent::Reset { stream_id: sid });
    }

    /// 握手帧（客户端：AUTH_OK 处理）
    ///
    /// 2026-08-20 公网 NAT 兼容修复：
    /// AUTH_OK 中的 data_port 是服务端为客户端分配的独立数据端口。
    /// 但 NAT 客户端发 PING 到 data_port 时 NAT 新建映射，服务端从
    /// data_port 回包源端口≠9000，对称 NAT 下入站被丢弃。
    /// 修复：不迁移端口，继续从 9000 收发（全双工 NAT 穿透）。
    /// data_port 保留给未来 STUN 打洞场景。
    fn on_handshake(&self, payload: &[u8]) {
        if !payload.is_empty() && payload[0] == crate::srt_shell::auth::CMD_AUTH_OK {
            self.authenticated.store(true, Ordering::Release);
            // 不迁移端口（公网 NAT 兼容）：继续从 9000 收发
            // data_port 解析但不使用（保留给未来 STUN 场景）
            match crate::srt_shell::auth::parse_auth_ok_port(payload) {
                Some(_port) => {
                    tracing::info!(data_port = _port, "认证成功（不迁移端口，NAT 兼容）");
                }
                None => {
                    tracing::warn!("AUTH_OK 端口解析失败（不迁移，走监听端口）");
                }
            }
        }
        let _ = self.rx_tx.send(RecvEvent::Control(payload.to_vec()));
    }

    // ========================================================================
    // 发送路径：流缓冲 -> 帧组装 -> 加密 -> 外壳 -> UDP
    // ========================================================================

    /// 唤醒发送线程（事件驱动，学 quic-go scheduleSending）
    ///
    /// 触发时机：send_msg 入队 / on_ack 释放预算 / on_pong RTT 更新。
    /// send_loop 无数据时 condvar wait，收到通知立即继续发。
    fn notify_send(&self) {
        let guard = self.send_trigger.lock().unwrap();
        self.send_cvar.notify_one();
        drop(guard);
    }

    /// 发送线程：流数据调度 + 周期 ACK + 心跳 PING + RTO 重传
    ///
    /// 2026-08-20 重构（学 quic-go 事件驱动 + CUBIC + pacer）：
    /// - **事件驱动**：无数据时 condvar wait（零 CPU），有数据/ACK
    ///   唤醒立即发。替代旧轮询 sleep(50µs)
    /// - **CUBIC + pacer**：cwnd by CUBIC，pacer rate = cwnd/srtt×5/4
    ///   （quic-go BandwidthEstimate，不靠带官认知回环下也正确）
    fn send_loop(&self) {
        let mut last_rto_check = Instant::now();
        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            let now = Instant::now();

            // 1. 取可发块（cwnd 预算 + pacer 预算；锁内决策）
            let out = {
                let mut st = self.state.lock().unwrap();
                let mut out: Vec<(u64, Vec<u8>, bool)> = Vec::new();

                // pacer 等待判定（quic-go SendPacingLimited）：
                // cwnd 够但 pacer 预算不足 -> 此轮不取数据
                let srtt = st.tracker.srtt();
                let pacer_wait = st.cong.time_until_send(now, srtt);

                // cwnd 预算（quic-go CanSend：in_flight < cwnd）
                let inflight = st.tracker.in_flight_bytes();
                let mut budget = st.cong.cwnd_bytes().saturating_sub(inflight);

                if budget > 0 && pacer_wait.is_none() {
                    let ids = st.streams.active_ids();
                    let mut blocks: Vec<(u32, u64, Vec<u8>, bool)> = Vec::new();
                    for id in ids {
                        if budget == 0 {
                            break;
                        }
                        if let Some(s) = st.streams.get(id) {
                            while budget > 0 {
                                if s.peek_block_len() > budget {
                                    break;
                                }
                                match s.take_block() {
                                    Some((offset, bytes, fin)) => {
                                        let n = bytes.len();
                                        budget = budget.saturating_sub(n);
                                        blocks.push((id, offset, bytes, fin));
                                        if fin {
                                            break;
                                        }
                                    }
                                    None => break,
                                }
                            }
                        }
                    }
                    for (id, offset, bytes, fin) in blocks {
                        let mut frame = Vec::with_capacity(bytes.len() + 16);
                        packet::encode_stream(&mut frame, id, offset, &bytes, fin);
                        let pkt_num = self.next_pkt_num.fetch_add(1, Ordering::Relaxed);
                        st.tracker.on_send(pkt_num, frame.clone(), true);
                        // CUBIC on_packet_sent（pacer 记账 + cwnd 通知）
                        let pkt_size = frame.len() + 32;
                        st.cong.on_packet_sent(now, pkt_num, pkt_size, true, srtt);
                        out.push((pkt_num, frame, true));
                    }
                }

                // 2. RTO 重传（每 ~50ms 检查）
                if last_rto_check.elapsed() >= Duration::from_millis(50) {
                    last_rto_check = now;
                    let expired = st.tracker.find_expired();
                    if !expired.is_empty() {
                        // CUBIC on_retransmission_timeout（quic-go 同款）
                        st.cong.on_retransmission_timeout(true);
                        let srtt2 = st.tracker.srtt();
                        for frame in expired {
                            let pkt_num = self.next_pkt_num.fetch_add(1, Ordering::Relaxed);
                            st.tracker.on_send(pkt_num, frame.clone(), true);
                            st.cong.on_packet_sent(now, pkt_num, frame.len() + 32, true, srtt2);
                            out.push((pkt_num, frame, true));
                        }
                    }
                }

                // 3. ACK 发送（quic-go：每 2 包立即 + 25ms 兜底）
                let send_ack = st.recv.should_send_ack_immediately()
                    || now.duration_since(st.last_ack_at) >= ACK_INTERVAL;
                if send_ack {
                    let (largest, ranges) = st.recv.ack_ranges(16);
                    if largest > 0 || !ranges.is_empty() {
                        let mut ack = Vec::new();
                        packet::encode_ack_ranges(&mut ack, largest, 0, &ranges);
                        out.push((0, ack, false));
                    }
                    st.last_ack_at = now;
                }

                (out, pacer_wait)
            };

            // 4. 锁外发送
            for (pkt_num, frame, is_data) in &out.0 {
                if *is_data {
                    self.send_frame_encrypted(frame, *pkt_num);
                } else {
                    self.send_ctrl_frame(frame);
                }
            }

            // 5. 心跳 PING（heartbeat_secs 周期；保活 + RTT；新包号）
            {
                let mut lp = self.last_ping.lock().unwrap();
                if lp.elapsed() >= Duration::from_secs(self.heartbeat_secs) {
                    let mut ping = Vec::with_capacity(9);
                    packet::encode_ping(&mut ping, &now_micros().to_be_bytes());
                    let pkt_num = self.next_pkt_num.fetch_add(1, Ordering::Relaxed);
                    self.send_frame_encrypted(&ping, pkt_num);
                    *lp = Instant::now();
                }
            }

            // 6. 断线检测：3×心跳周期无任何接收
            {
                let st = self.state.lock().unwrap();
                if st.last_recv_at.elapsed() > Duration::from_secs(self.heartbeat_secs * 3) {
                    tracing::warn!("连接超时（无数据），标记断开");
                    drop(st);
                    self.closed.store(true, Ordering::Release);
                    break;
                }
            }

            // 7. 事件驱动等待（学 quic-go Run() select）：
            // 有数据发出 -> 立即下一轮（光速循环，CPU 换吞吐）
            // 无数据发出 -> condvar wait 直到 notify_send 唤醒
            // pacer 限制 -> 等待 pacer_time_until_send 时长
            if out.0.is_empty() {
                let wait = match out.1 {
                    // pacer 限制：等 pacer 恢复（100µs 细粒度，回环高带宽关键）
                    Some(d) => d.min(Duration::from_micros(100)),
                    // 无数据：等唤醒或 1ms 超时保底（防丢失 notify_send；
                    // 回环 ACK~150µs，1ms 足够响应）
                    None => Duration::from_millis(1),
                };
                let guard = self.send_trigger.lock().unwrap();
                let _ = self.send_cvar.wait_timeout(guard, wait);
            }
        }
    }

    /// 发送数据帧（AES-128-CTR 加密 + 数据壳 + 包号写 SEQ 字段）
    ///
    /// 包号由调用方分配传入（统一 fetch_add，确保所有数据壳包唯一编号；
    /// 重传 = 删旧条目 + 新包号新包，标准 QUIC 语义）。
    /// 加密 nonce = [连接前缀 8B | 包号 8B]，包号唯一保证密钥流不重复。
    #[cfg(not(feature = "no-crypto"))]
    fn send_frame_encrypted(&self, frame: &[u8], pkt_num: u64) {
        // AES-128-CTR 加密（nonce 内含包号，无需额外 rand 系统调用）
        let encrypted = self.cipher.encrypt_packet(pkt_num, frame);
        // 数据壳（bit31=0，包号写 SEQ 字段）
        let pkt = crate::srt_shell::outer::encode_data_packet_v2(&encrypted, pkt_num as u32);
        self.send_udp(&pkt);
    }

    /// 不加密直通版（no-crypto 特性；**仅性能基准，严禁生产**）
    #[cfg(feature = "no-crypto")]
    fn send_frame_encrypted(&self, frame: &[u8], pkt_num: u64) {
        // 明文：直接 frame 作 inner（不调用 cipher）
        let pkt = crate::srt_shell::outer::encode_data_packet_v2(frame, pkt_num as u32);
        self.send_udp(&pkt);
    }

    /// 发送控制帧（明文控制壳；ACK 等）
    fn send_ctrl_frame(&self, frame: &[u8]) {
        // ACK 帧走 SRT ACK 控制壳（0x80 02 00 00）
        let pkt = crate::srt_shell::outer::encode_ack_ctrl_packet(frame);
        self.send_udp(&pkt);
    }

    /// UDP 发送（EAGAIN 短自旋重试）
    fn send_udp(&self, pkt: &[u8]) {
        let target = self.send_target();
        for _ in 0..200 {
            match self.udp.send_to(pkt, target) {
                Ok(_) => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_micros(50));
                }
                Err(_) => return, // 不可达等：放弃（ACK 丢失下周期补发/数据靠重传）
            }
        }
    }

    /// 当前发送目标（端口迁移后 = peer IP + data_port）
    fn send_target(&self) -> SocketAddr {
        let port = self.data_only_port.load(Ordering::Acquire);
        if port != 0 {
            SocketAddr::new(self.peer.ip(), port)
        } else {
            self.peer
        }
    }

    /// 发送 SRT 特征握手（客户端 AUTH）
    fn send_handshake(&self) -> io::Result<()> {
        let nonce: [u8; 12] = {
            use rand::RngCore;
            let mut n = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut n);
            n
        };
        let auth_payload = crate::srt_shell::auth::auth_request(&self.secret, &nonce);
        let mut inner = Vec::new();
        packet::encode_handshake(&mut inner, &auth_payload);
        let pkt = crate::srt_shell::outer::encode_ctrl_packet(
            crate::srt_shell::header::MSG_HANDSHAKE,
            0,
            &inner,
        );
        // 握手期间端口未迁移，直接发 peer
        let _ = self.udp.send_to(&pkt, self.peer);
        Ok(())
    }

    // ========================================================================
    // 上层 API（与 v1 兼容）
    // ========================================================================

    /// 发送一条完整消息（前端 Mux 帧；写入主流缓冲，send_loop 调度）
    ///
    /// 背压语义：缓冲满时自旋等待（连接关闭返回 false）。
    ///
    /// 2026-08-20 v2 事件驱动：入队后 notify_send 唤醒 send_loop，
    /// 替代旧的"等下次轮询"延迟。
    pub fn send_msg(&self, data: &[u8]) -> bool {
        loop {
            if self.closed.load(Ordering::Acquire) {
                return false;
            }
            {
                let mut st = self.state.lock().unwrap();
                if !st.streams.exists(MAIN_STREAM_ID) {
                    st.streams.open(MAIN_STREAM_ID);
                }
                if let Some(s) = st.streams.get(MAIN_STREAM_ID) {
                    if s.send(data) == data.len() {
                        // 入队成功，唤醒发送线程（学 quic-go onHasStreamData -> scheduleSending）
                        drop(st);
                        self.notify_send();
                        return true;
                    }
                }
            }
            // 缓冲满，背压等待
            std::thread::sleep(Duration::from_micros(50));
        }
    }

    /// 前端兼容发送（v1 签名）
    pub fn send(&self, data: Vec<u8>) -> Result<(), String> {
        if self.send_msg(&data) {
            Ok(())
        } else {
            Err("发送失败（连接已关闭）".to_string())
        }
    }

    /// 前端兼容异步发送（v1 签名）
    pub async fn send_async(&self, data: Vec<u8>) -> Result<(), String> {
        self.send(data)
    }

    /// 取走事件流（上层消费；单消费者）
    pub fn take_events(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<RecvEvent>> {
        self.rx_rx.lock().unwrap().take()
    }

    /// 是否已断开（上层重连逻辑轮询；P1.5 监控接入时启用）
    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// 主动关闭（预留优雅关闭；当前由重连/进程退出终结）
    #[allow(dead_code)]
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// 线协议帧（解码后的分流表示）
enum WireFrame {
    /// STREAM 帧（原始字节，on_stream_frame 再解析）
    Data(Vec<u8>),
    /// ACK（largest, delay, ranges）
    Ack(u64, u32, Vec<(u64, u64)>),
    /// PING 载荷
    Ping(Vec<u8>),
    /// PONG 载荷
    Pong(Vec<u8>),
    /// RST_STREAM
    Rst(u32, u32),
    /// 握手载荷
    Handshake(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 配置默认值（v1 兼容）
    #[test]
    fn test_config_defaults() {
        let cfg = QuicConfig::default();
        assert_eq!(cfg.init_cwnd_packets, 16);
        assert_eq!(cfg.heartbeat_secs, 5);
        assert!(cfg.peer.is_none());
    }
}
