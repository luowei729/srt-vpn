//! quinn-proto 驱动循环模块（v2 完整重写）
//!
//! 设计原因：quinn-proto 是纯状态机（无 I/O），需要自管 UdpSocket + 定时器。
//! 用 tokio select! 桥接三类事件源：UdpSocket 就绪 / 定时器到期 / 应用请求。
//!
//! 数据流：
//! ```
//! 收包: UdpSocket.recv_from -> 去RTP头 -> 取包号 -> AES解密 -> endpoint.handle()
//! 发包: conn.poll_transmit -> AES加密 -> [8B包号|密文] -> 套RTP头 -> socket.try_send_to
//! ```
//!
//! ## v0.4.7 RTP 外壳（2026-08-22，伪装目标从 SRT 升级为 RTP）
//!
//! 抓包研究结论：真实 RTP 视频流（H264 PT=96 / 90000Hz）首字节固定 0x80（V=2），
//! SEQ 连续 +1，TS 每帧跳 3000，M 帧尾置 1，SSRC 会话内不变；而 SRT 数据包首字节
//! bit31=0（0x00-0x7F）被判"未知 UDP"。故将外壳改为 RFC3550 RTP 头（12B）：
//! [V=2|P|X|CC][M|PT=96][SEQ 16b][TS 32b][SSRC 32b][8B包号|AES密文]。
//! 接收端双模式兼容：首字节 V=2 按 RTP 解析，否则回退旧 SRT 外壳（升级期互通）。
//!
//! ## v2 重写修复的 bug（2026-08-21 传输层完整审查）
//!
//! 1. **MTU 探测失控（"too many gaps" 断连根因）**：
//!    allow_mtud=true 在回环（MTU 65536）上探测出巨型 QUIC 包，加 RTP 头
//!    后超过对端 65535 接收缓冲被截断丢弃 -> 接收流缓冲大量空洞 -> 连接自杀。
//!    修复：禁用 MTU 探测（mtu_discovery_config(None)），固定 initial_mtu=1200。
//!    注意：RTP 头 12B 意味着 wire 上 1212B，仍在以太网 MTU 1500 内。
//!
//! 2. **发送阻塞接收（74KB/s 低速根因）**：
//!    旧版 flush_sends 用 send_to().await，wmem 满（内核 wmem_max 默认 208KB
//!    会钳制 SO_SNDBUF）时整个 driver 单线程挂起 -> 不再收包 -> ACK 发不出
//!    -> 对端拥塞窗口收缩 -> 恶性循环。
//!    修复：改用 try_send_to 非阻塞发送；EAGAIN 时包重排队（不能丢，QUIC 包
//!    丢了等于私自丢包破坏状态机），并立即回到 select! 让 socket 可写事件
//!    唤醒后重试。
//!
//! 3. **accept 流竞态（数据黑洞）**：
//!    旧版 accept 到流就发 StreamReadable，但此时流可能还没有数据（STREAM
//!    帧后到）。应用层读流得到空 -> 标记 handled -> 真数据到达被永久跳过。
//!    修复：accept 不发事件，等 quinn-proto 的 Readable 事件再通知（Readable
//!    才是"确有数据"的权威信号）。
//!
//! 4. **流数据在 driver 内缓冲 + waiter 唤醒（消除 10ms 轮询）**：
//!    旧版应用层 request_stream_read + sleep(10ms) 轮询，每块数据至少延迟
//!    10ms，吞吐被钳制在 ~80KB/s（8KB 块 × 100 次/秒）。
//!    修复：driver 在 Readable 事件时就地把流数据读出存入 per-stream 缓冲
//!    （VecDeque），并唤醒等待该流的 reader（tokio::sync::Notify）。应用层
//!    read_stream() 在无数据时 await Notify，有数据立即返回。
//!    这同时消除了"事件发给应用层 + 数据留在 driver"的两处状态脱节问题。
//!
//! 5. **Blocked 当致命错误（转发任务死亡）**：
//!    旧版 StreamWrite 返回 Blocked 时转发任务直接 break 退出（数据黑洞 +
//!    连接泄漏）。修复：driver 维护发送重试队列，应用层只需写一次。
//!
//! 6. **多客户端路由错误**：
//!    旧版 handle_request 无 conn_handle 时"取第一个连接"，多客户端场景
//!    stream_id 会路由到错误连接（stream_id 在不同连接间独立重复）。
//!    修复：driver 维护 stream_id -> ConnectionHandle 映射表，精确路由。
//!
//! 7. **性能细节**：
//!    - 每包 clone 64KB 缓冲 -> 直接原地加解密
//!    - local_addr() 每包系统调用 -> 启动时缓存一次
//!    - flush_sends 每包 rand::random() 3 次 -> 用 SEQ 计数器

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig,
    ServerConfig, StreamId, TransportConfig, VarInt,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::transport::crypto::PacketCipher;
use crate::transport::rtp_shell::{RTP_PKTNUM_LEN, RtpPacket};
use crate::transport::srt_shell::SrtPacket;

/// UDP 接收缓冲区大小（单个 UDP 数据报最大 65507 + 16B SRT 头）
const RECV_BUF_SIZE: usize = 65535;

/// 流数据缓冲的单块上限（单次 STREAM 帧数据的读取粒度）
const STREAM_READ_CHUNK: usize = 256 * 1024;

/// 应用层向驱动层发送的请求
#[derive(Debug)]
pub enum DriverRequest {
    /// 打开双向流（客户端发 Connect 命令用）
    OpenBiStream {
        reply: oneshot::Sender<Result<StreamId, DriverError>>,
    },
    /// 向流写入数据（Blocked 时由 driver 内部队列接管重试）
    StreamWrite {
        stream_id: StreamId,
        data: bytes::Bytes,
        reply: oneshot::Sender<Result<usize, DriverError>>,
    },
    /// 结束流的发送方向（发送 FIN）
    StreamFinish {
        stream_id: StreamId,
        reply: oneshot::Sender<Result<(), DriverError>>,
    },
    /// 重置流（发送 RESET_STREAM）
    StreamReset {
        stream_id: StreamId,
        error_code: u64,
        reply: oneshot::Sender<Result<(), DriverError>>,
    },
    /// 停止流的接收方向（发送 STOP_SENDING）
    StreamStop {
        stream_id: StreamId,
        error_code: u64,
        reply: oneshot::Sender<Result<(), DriverError>>,
    },
    /// 从流读取数据（无数据时挂起等待，有数据立即返回）
    StreamRead {
        stream_id: StreamId,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, DriverError>>,
    },
    /// 发送 TUIC 命令（通过 uni-stream，如 Authenticate/Heartbeat）
    SendUniStream {
        data: bytes::Bytes,
        reply: oneshot::Sender<Result<(), DriverError>>,
    },
    /// 关闭连接
    Close {
        reply: oneshot::Sender<()>,
    },
    /// 获取 TLS exporter 密钥材料（TUIC 认证用）
    ExportKeyingMaterial {
        output_len: usize,
        label: Vec<u8>,
        context: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, DriverError>>,
    },
}

/// 驱动层向应用层推送的事件
#[derive(Debug)]
pub enum DriverEvent {
    /// 流有数据可读（driver 内缓冲已有数据，应用层发 StreamRead 立即返回）
    StreamReadable { stream_id: StreamId },
    /// 流已结束（FIN，无更多数据；读流会得到 None）
    StreamFinished { stream_id: StreamId },
    /// 流被对端重置
    StreamStopped { stream_id: StreamId, error_code: u64 },
    /// 连接已建立
    Connected,
    /// 连接已关闭
    ConnectionLost { reason: String },
}

/// 驱动层错误
#[derive(Debug)]
pub enum DriverError {
    NotConnected,
    ClosedStream,
    ConnectionLost(String),
    Other(String),
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConnected => write!(f, "连接未建立"),
            Self::ClosedStream => write!(f, "流已关闭"),
            Self::ConnectionLost(r) => write!(f, "连接丢失: {}", r),
            Self::Other(e) => write!(f, "驱动错误: {}", e),
        }
    }
}

impl std::error::Error for DriverError {}

/// 单条流的接收状态（driver 内缓冲 + 待回复的读取请求）
struct StreamRecvState {
    /// 已到达的流数据块队列（driver 在 Readable 事件时填充）
    buffer: VecDeque<Vec<u8>>,
    /// 流是否已结束（收到 FIN）
    finished: bool,
    /// 流是否被对端重置
    reset: bool,
    /// 待回复的读取请求（无数据时暂存，数据到达时立即回复）
    pending_reply: Option<oneshot::Sender<Result<Option<Vec<u8>>, DriverError>>>,
}

impl StreamRecvState {
    fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
            finished: false,
            reset: false,
            pending_reply: None,
        }
    }
}

/// 待重试的流写入（Blocked 后排队）
struct PendingWrite {
    stream_id: StreamId,
    data: bytes::Bytes,
    reply: Option<oneshot::Sender<Result<usize, DriverError>>>,
}

/// QUIC 传输驱动器（v2）
pub struct TransportDriver {
    endpoint: Endpoint,
    /// 连接表
    connections: HashMap<ConnectionHandle, Connection>,
    /// stream_id -> 连接句柄 映射（多客户端精确路由，写请求用）
    stream_route: HashMap<StreamId, ConnectionHandle>,
    socket: Arc<UdpSocket>,
    /// 包级加密器
    cipher: PacketCipher,
    /// 对端地址（客户端模式固定；服务端模式从包源地址学习）
    peer_addr: Option<SocketAddr>,
    /// 主连接句柄
    conn_handle: Option<ConnectionHandle>,
    req_rx: mpsc::UnboundedReceiver<DriverRequest>,
    event_tx: mpsc::UnboundedSender<DriverEvent>,
    is_server: bool,
    /// 流接收状态表（stream_id -> 缓冲 + 唤醒器）
    stream_recv: HashMap<StreamId, StreamRecvState>,
    /// Blocked 待重写的队列
    pending_writes: VecDeque<PendingWrite>,
    /// 缓存的本地 IP（避免每包系统调用）
    cached_local_ip: Option<std::net::IpAddr>,
    /// RTP 外壳序号（16bit，每包 +1，回绕，替代每包 rand）
    srt_seq: u32,
    /// RTP SSRC（同步源 ID，每连接随机固定，RTP 会话内不变）
    rtp_ssrc: u32,
    /// 最近一次注入 RTCP SR 的时间（周期注入控制通道，满足要求 RTP+RTCP 成对的 DPI）
    last_rtcp_at: Option<Instant>,
    /// RTCP SR 累计发送包数/字节数（SR 载荷字段，模拟真实发送统计）
    rtcp_pkt_count: u32,
    rtcp_octet_count: u32,
    /// 是否有 socket 可写事件待处理（发送 EAGAIN 后置位）
    send_blocked: bool,
    /// EAGAIN 时重排队的 QUIC 包（QUIC 包不能丢，丢了破坏状态机）
    queued_packet: Option<(quinn_proto::Transmit, Vec<u8>)>,
}

impl TransportDriver {
    /// 创建客户端传输驱动器
    pub fn new_client(
        socket: Arc<UdpSocket>,
        server_addr: SocketAddr,
        server_name: &str,
        passphrase: &str,
        req_rx: mpsc::UnboundedReceiver<DriverRequest>,
        event_tx: mpsc::UnboundedSender<DriverEvent>,
    ) -> Result<Self, DriverError> {
        let crypto = rustls::client::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerification))
            .with_no_client_auth();
        let quic_config = QuicClientConfig::try_from(crypto)
            .map_err(|e| DriverError::Other(format!("QUIC 客户端配置失败: {}", e)))?;

        let transport_config = build_transport_config();
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = Endpoint::new(
            Arc::new(EndpointConfig::default()),
            None,
            false, // allow_mtud=false：禁用 MTU 探测（见模块注释 bug#1）
            None,
        );

        // 发起 QUIC 连接
        let now = Instant::now();
        let (conn_handle, conn) = endpoint
            .connect(now, client_config, server_addr, server_name)
            .map_err(|e| DriverError::Other(format!("QUIC 连接失败: {}", e)))?;

        // 派生临时加密密钥（阶段 1：TLS 握手前；两端 passphrase 相同）
        let temp_key = PacketCipher::derive_temp_key(passphrase);
        let conn_prefix = PacketCipher::derive_conn_prefix(passphrase);
        let cipher = PacketCipher::new(temp_key, conn_prefix);

        let mut connections = HashMap::new();
        connections.insert(conn_handle, conn);

        Ok(Self {
            endpoint,
            connections,
            stream_route: HashMap::new(),
            socket,
            cipher,
            peer_addr: Some(server_addr),
            conn_handle: Some(conn_handle),
            req_rx,
            event_tx,
            is_server: false,
            stream_recv: HashMap::new(),
            pending_writes: VecDeque::new(),
            cached_local_ip: None,
            srt_seq: 0,
            rtp_ssrc: rand::random::<u32>() | 0x8000_0000, // SSRC 高位通常非 0 拟真
            last_rtcp_at: None,
            rtcp_pkt_count: 0,
            rtcp_octet_count: 0,
            send_blocked: false,
            queued_packet: None,
        })
    }

    /// 创建服务端传输驱动器
    pub fn new_server(
        socket: Arc<UdpSocket>,
        cert_pem: &[u8],
        key_pem: &[u8],
        passphrase: &str,
        req_rx: mpsc::UnboundedReceiver<DriverRequest>,
        event_tx: mpsc::UnboundedSender<DriverEvent>,
    ) -> Result<Self, DriverError> {
        let cert_chain: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DriverError::Other(format!("证书加载失败: {}", e)))?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_ref())
            .map_err(|e| DriverError::Other(format!("私钥加载失败: {}", e)))?
            .ok_or_else(|| DriverError::Other("私钥为空".into()))?;

        let server_crypto = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| DriverError::Other(format!("TLS 配置失败: {}", e)))?;
        let quic_config = QuicServerConfig::try_from(server_crypto)
            .map_err(|e| DriverError::Other(format!("QUIC 服务端配置失败: {}", e)))?;

        let transport_config = build_transport_config();
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_config));
        server_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(Arc::new(server_config)),
            false, // allow_mtud=false：禁用 MTU 探测
            None,
        );

        let temp_key = PacketCipher::derive_temp_key(passphrase);
        let conn_prefix = PacketCipher::derive_conn_prefix(passphrase);
        let cipher = PacketCipher::new(temp_key, conn_prefix);

        Ok(Self {
            endpoint,
            connections: HashMap::new(),
            stream_route: HashMap::new(),
            socket,
            cipher,
            peer_addr: None,
            conn_handle: None,
            req_rx,
            event_tx,
            is_server: true,
            stream_recv: HashMap::new(),
            pending_writes: VecDeque::new(),
            cached_local_ip: None,
            srt_seq: 0,
            rtp_ssrc: rand::random::<u32>() | 0x8000_0000,
            last_rtcp_at: None,
            rtcp_pkt_count: 0,
            rtcp_octet_count: 0,
            send_blocked: false,
            queued_packet: None,
        })
    }

    /// 运行驱动循环（主事件循环）
    pub async fn run(mut self) {
        tracing::info!("传输驱动器启动");

        let mut recv_buf = vec![0u8; RECV_BUF_SIZE];
        let mut send_buf = Vec::with_capacity(RECV_BUF_SIZE);

        // 缓存本地 IP（避免每包系统调用）
        self.cached_local_ip = self.socket.local_addr().ok().and_then(|a| match a {
            SocketAddr::V4(a) => Some(std::net::IpAddr::V4(*a.ip())),
            SocketAddr::V6(a) => Some(std::net::IpAddr::V6(*a.ip())),
        });

        // 首次 flush：客户端 connect 后立即发送 QUIC Initial 包
        // （quinn-proto 的包在 poll_transmit 时才生成）
        self.drain_and_flush(&mut send_buf);

        loop {
            // select! 前先算好超时时长（避免 select! 内 self 可变借用冲突）
            let timeout = self.compute_timeout();
            let has_timer = self.next_timeout().is_some();

            tokio::select! {
                // === 1. UdpSocket 可读 ===
                result = self.socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((len, src_addr)) => {
                            self.handle_recv(&recv_buf[..len], src_addr, &mut send_buf);
                            // 批量排空接收缓冲区（单包 select 是吞吐瓶颈）
                            loop {
                                match self.socket.try_recv_from(&mut recv_buf) {
                                    Ok((len2, src2)) => {
                                        self.handle_recv(&recv_buf[..len2], src2, &mut send_buf);
                                    }
                                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                                    Err(e) => {
                                        tracing::error!(error = %e, "UDP 批量接收失败");
                                        break;
                                    }
                                }
                            }
                            self.drain_and_flush(&mut send_buf);
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "UDP 接收失败");
                            break;
                        }
                    }
                }

                // === 2. socket 可写（仅在发送阻塞后等待，两个 &self 借用无冲突） ===
                _ = self.socket.writable(), if self.send_blocked => {
                    self.send_blocked = false;
                    // 先重发 EAGAIN 时排队的包，再继续正常发送
                    self.retry_queued_packet();
                    self.drain_and_flush(&mut send_buf);
                }

                // === 3. 定时器到期（quinn-proto 超时：ACK/重传/保活） ===
                _ = tokio::time::sleep(timeout), if has_timer => {
                    self.handle_timeout(Instant::now());
                    self.drain_and_flush(&mut send_buf);
                }

                // === 4. 应用层请求 ===
                req = self.req_rx.recv() => {
                    match req {
                        Some(request) => {
                            self.handle_request(request);
                            self.drain_and_flush(&mut send_buf);
                        }
                        None => {
                            tracing::info!("应用层关闭，驱动器退出");
                            break;
                        }
                    }
                }
            }
        }

        tracing::info!("传输驱动器退出");
    }

    /// 排空 quinn-proto 事件队列并发送所有待发包
    fn drain_and_flush(&mut self, send_buf: &mut Vec<u8>) {
        // 迭代上限：防止大量待发包时单次 drain 占满单核导致假死（hk2 单核 1.9G 测出 5MB 卡死）
        // 32 在公网高吞吐下成为瓶颈，放宽到 128（单轮最多 128 包，仍让出 select! 但保证 50MB/s+）
        const MAX_ITERS: usize = 128;
        for _ in 0..MAX_ITERS {
            self.poll_events();
            self.poll_endpoint_events();
            self.retry_pending_writes();
            let sent = self.flush_sends(send_buf);
            // 无事件且无包可发时退出循环（避免忙转）
            if !sent && !self.has_events() {
                break;
            }
            if !sent {
                break;
            }
        }
    }

    /// 是否还有未处理事件（快速探测）
    fn has_events(&self) -> bool {
        !self.pending_writes.is_empty() && !self.send_blocked
    }

    /// 计算下一次超时时间
    fn compute_timeout(&mut self) -> Duration {
        if let Some(t) = self.next_timeout() {
            let now = Instant::now();
            if t > now {
                t - now
            } else {
                Duration::from_millis(5)
            }
        } else {
            Duration::from_secs(10)
        }
    }

    /// 获取所有连接的最早超时时间
    fn next_timeout(&mut self) -> Option<Instant> {
        self.connections
            .values_mut()
            .filter_map(|conn| conn.poll_timeout())
            .min()
    }

    /// 处理定时器到期
    fn handle_timeout(&mut self, now: Instant) {
        for conn in self.connections.values_mut() {
            conn.handle_timeout(now);
        }
    }

    /// 处理接收到的 UDP 包
    ///
    /// 数据流: UDP recv -> 去RTP外壳 -> 取包号 -> AES解密 -> endpoint.handle()
    ///
    /// 兼容双模式：
    /// - RTP 外壳（新，v0.4.7+）：首字节 V=2（0x80），负载 [8B 包号][密文]
    /// - RTCP SR（伪装控制包，PT=200）：对端注入的假视频控制通道，无 QUIC 数据，静默丢弃
    /// - SRT 外壳（旧，历史）：首字节 bit31=0/1，packet_num 在 msg_no 字段，
    ///   固定包按 2B 长度前缀还原（升级期间双端版本可能交错，必须兼容）
    fn handle_recv(&mut self, data: &[u8], src_addr: SocketAddr, send_buf: &mut Vec<u8>) {
        // 服务端学习对端地址（用于 accept 时路由；客户端固定）
        if self.is_server && self.peer_addr.is_none() {
            self.peer_addr = Some(src_addr);
        }

        // 0. RTCP SR 伪装包：仅用于让 DPI 看到 RTP+RTCP 成对会话，无业务数据，直接忽略
        if crate::transport::rtp_shell::is_rtcp_sr(data) {
            return;
        }

        // 1. 优先按 RTP 外壳解析（V=2，首字节 0x80-0xBF）
        let packet_num: u64;
        let ciphertext: Vec<u8>;
        if data.len() >= crate::transport::rtp_shell::RTP_HEADER_LEN
            && (data[0] >> 6) & 0x3 == 2
        {
            let rtp = match RtpPacket::decode(data) {
                Ok(p) => p,
                Err(_) => return, // 非 RTP 包静默丢弃
            };
            packet_num = match rtp.packet_num() {
                Some(n) => n,
                None => return, // 载荷缺包号前缀
            };
            ciphertext = rtp.ciphertext().to_vec();
        } else {
            // 2. 回退旧 SRT 外壳（升级期间兼容旧对端）
            let srt_packet = match SrtPacket::decode(data) {
                Ok(pkt) => pkt,
                Err(_) => return, // 非 SRT 包静默丢弃（可能是端口扫描）
            };
            packet_num = match &srt_packet {
                SrtPacket::Data { msg_no, .. } => *msg_no as u64,
                SrtPacket::Control { msg_no, .. } => *msg_no as u64,
            };
            let payload_bytes = srt_packet.payload().to_vec();
            ciphertext = if payload_bytes.len() == crate::transport::srt_shell::SRT_DATA_PAYLOAD_SIZE {
                crate::transport::srt_shell::unpack_fixed_payload(&payload_bytes)
            } else {
                payload_bytes
            };
        }

        // 3. AES 解密（nonce = [连接前缀][包号]，见 crypto.rs）
        let plaintext = match self
            .cipher
            .decrypt_with_nonce(&ciphertext, self.cipher.conn_prefix(), packet_num)
        {
            Ok(p) => p,
            Err(_) => return, // 解密失败静默丢弃
        };

        // 4. 喂给 quinn-proto Endpoint 处理
        let now = Instant::now();
        let data_mut = BytesMut::from(&plaintext[..]);
        if let Some(event) = self.endpoint.handle(
            now,
            src_addr,
            self.cached_local_ip,
            None,
            data_mut,
            send_buf,
        ) {
            self.handle_datagram_event(event, src_addr, send_buf);
        }
    }

    /// 处理 quinn-proto 的 DatagramEvent
    fn handle_datagram_event(
        &mut self,
        event: DatagramEvent,
        remote: SocketAddr,
        send_buf: &mut Vec<u8>,
    ) {
        match event {
            DatagramEvent::NewConnection(incoming) => {
                if self.is_server {
                    let now = Instant::now();
                    match self.endpoint.accept(incoming, now, send_buf, None) {
                        Ok((conn_handle, conn)) => {
                            tracing::info!(?remote, ?conn_handle, "新连接接入");
                            self.connections.insert(conn_handle, conn);
                            // 服务端单客户端场景：总是把主连接句柄指向最新连接。
                            // 修复：旧逻辑只在 is_none() 时设置，导致客户端重连后
                            // ExportKeyingMaterial/Close 等无 stream_id 的请求仍路由到
                            // 第一个（已死）连接的 TLS session，token 派生不一致 →
                            // "认证失败（token 不匹配）"。旧连接 Drained 时会被清为
                            // None，但新旧连接事件可能交错，必须以最新为准。
                            self.conn_handle = Some(conn_handle);
                        }
                        Err(e) => {
                            tracing::warn!(error = ?e, "接受连接失败");
                        }
                    }
                }
            }
            DatagramEvent::ConnectionEvent(conn_handle, conn_event) => {
                if let Some(conn) = self.connections.get_mut(&conn_handle) {
                    conn.handle_event(conn_event);
                }
            }
            DatagramEvent::Response(transmit) => {
                // Endpoint 直接生成的响应（版本协商/无状态重置）
                // 从 send_buf 取出该 transmit 对应的数据立即加密发送
                let pkt = send_buf[..transmit.size.min(send_buf.len())].to_vec();
                self.send_wire_packet(&transmit.destination, &pkt);
            }
        }
    }

    /// 处理应用层请求
    ///
    /// stream_id -> 连接的精确路由（多客户端场景 stream_id 会重复）
    fn handle_request(&mut self, req: DriverRequest) {
        // 提取请求关联的 stream_id（用于路由）
        let req_stream = match &req {
            DriverRequest::StreamWrite { stream_id, .. }
            | DriverRequest::StreamFinish { stream_id, .. }
            | DriverRequest::StreamReset { stream_id, .. }
            | DriverRequest::StreamStop { stream_id, .. }
            | DriverRequest::StreamRead { stream_id, .. } => Some(*stream_id),
            _ => None,
        };

        // 路由决策：stream_route 精确查找 > conn_handle > 单连接 fallback
        let conn_handle = if let Some(sid) = req_stream {
            if let Some(ch) = self.stream_route.get(&sid) {
                *ch
            } else if let Some(ch) = self.conn_handle {
                ch
            } else {
                self.reply_error(req, DriverError::NotConnected);
                return;
            }
        } else if let Some(ch) = self.conn_handle {
            ch
        } else if let Some(ch) = self.connections.keys().next().cloned() {
            self.conn_handle = Some(ch);
            ch
        } else {
            self.reply_error(req, DriverError::NotConnected);
            return;
        };

        let conn = match self.connections.get_mut(&conn_handle) {
            Some(c) => c,
            None => {
                self.reply_error(req, DriverError::NotConnected);
                return;
            }
        };

        match req {
            DriverRequest::OpenBiStream { reply } => {
                let mut streams = conn.streams();
                match streams.open(Dir::Bi) {
                    Some(stream_id) => {
                        // 登记路由（此流由本连接承载）
                        self.stream_route.insert(stream_id, conn_handle);
                        let _ = reply.send(Ok(stream_id));
                    }
                    None => {
                        // 流额度耗尽（对端 MAX_STREAMS 限制）
                        let _ = reply.send(Err(DriverError::Other("流额度耗尽".into())));
                    }
                }
            }
            DriverRequest::StreamWrite {
                stream_id,
                data,
                reply,
            } => {
                let mut send_stream = conn.send_stream(stream_id);
                match send_stream.write(&data) {
                    Ok(n) => {
                        let _ = reply.send(Ok(n));
                    }
                    Err(quinn_proto::WriteError::Blocked) => {
                        // 流控阻塞：进入重试队列（由 Writable 事件驱动重写）
                        self.pending_writes.push_back(PendingWrite {
                            stream_id,
                            data,
                            reply: Some(reply),
                        });
                    }
                    Err(e) => {
                        let _ = reply.send(Err(DriverError::Other(format!("写入失败: {}", e))));
                    }
                }
            }
            DriverRequest::StreamFinish { stream_id, reply } => {
                let mut send_stream = conn.send_stream(stream_id);
                match send_stream.finish() {
                    Ok(()) => {
                        let _ = reply.send(Ok(()));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(DriverError::Other(format!("FIN 失败: {}", e))));
                    }
                }
            }
            DriverRequest::StreamReset {
                stream_id,
                error_code,
                reply,
            } => {
                let mut send_stream = conn.send_stream(stream_id);
                let _ =
                    send_stream.reset(VarInt::from_u64(error_code).unwrap_or(VarInt::from_u32(0)));
                let _ = reply.send(Ok(()));
            }
            DriverRequest::StreamStop {
                stream_id,
                error_code,
                reply,
            } => {
                let mut recv_stream = conn.recv_stream(stream_id);
                let _ =
                    recv_stream.stop(VarInt::from_u64(error_code).unwrap_or(VarInt::from_u32(0)));
                let _ = reply.send(Ok(()));
            }
            DriverRequest::StreamRead { stream_id, reply } => {
                // 从 driver 内缓冲读取；无数据时注册等待（不立即回复）
                self.handle_stream_read(stream_id, reply);
            }
            DriverRequest::SendUniStream { data, reply } => {
                let mut streams = conn.streams();
                match streams.open(Dir::Uni) {
                    Some(stream_id) => {
                        self.stream_route.insert(stream_id, conn_handle);
                        let mut send_stream = conn.send_stream(stream_id);
                        match send_stream.write(&data) {
                            Ok(_) => {
                                let _ = send_stream.finish();
                                let _ = reply.send(Ok(()));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(DriverError::Other(format!(
                                    "uni-stream 写入失败: {}",
                                    e
                                ))));
                            }
                        }
                    }
                    None => {
                        let _ = reply.send(Err(DriverError::Other("流额度耗尽".into())));
                    }
                }
            }
            DriverRequest::Close { reply } => {
                conn.close(Instant::now(), VarInt::from_u32(0), bytes::Bytes::new());
                let _ = reply.send(());
            }
            DriverRequest::ExportKeyingMaterial {
                output_len,
                label,
                context,
                reply,
            } => {
                let session = conn.crypto_session();
                let mut output = vec![0u8; output_len];
                match session.export_keying_material(&mut output, &label, &context) {
                    Ok(()) => {
                        let _ = reply.send(Ok(output));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(DriverError::Other(format!(
                            "TLS exporter 失败: {:?}",
                            e
                        ))));
                    }
                }
            }
        }
    }

    /// 处理流读取请求（driver 内缓冲 + pending reply 模式）
    ///
    /// 有数据立即回复；无数据暂存 reply（Readable 事件到达时回复）。
    /// 消除旧版 10ms 轮询：reader 在 driver 事件路径上被同步唤醒。
    fn handle_stream_read(
        &mut self,
        stream_id: StreamId,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, DriverError>>,
    ) {
        // 确保流接收状态存在
        let state = self
            .stream_recv
            .entry(stream_id)
            .or_insert_with(StreamRecvState::new);

        if let Some(data) = state.buffer.pop_front() {
            // 缓冲有数据，立即回复
            let _ = reply.send(Ok(Some(data)));
            return;
        }
        if state.finished {
            let _ = reply.send(Ok(None)); // FIN
            return;
        }
        if state.reset {
            let _ = reply.send(Err(DriverError::ClosedStream));
            return;
        }

        // 无数据：暂存 reply（同一流只允许一个挂起的读请求）
        if state.pending_reply.is_some() {
            // 已有等待者（应用层不应并发读同一流）：旧回复被丢弃
            tracing::warn!(?stream_id, "流已有挂起的读取请求，覆盖旧请求");
        }
        state.pending_reply = Some(reply);
    }

    /// 尝试回复挂起的读取请求（数据入缓冲/FIN/Reset 后调用）
    fn flush_pending_reply(&mut self, stream_id: StreamId) {
        let state = match self.stream_recv.get_mut(&stream_id) {
            Some(s) => s,
            None => return,
        };

        if let Some(reply) = state.pending_reply.take() {
            if let Some(data) = state.buffer.pop_front() {
                // 有数据：立即回复
                let _ = reply.send(Ok(Some(data)));
            } else if state.finished {
                let _ = reply.send(Ok(None)); // FIN
            } else if state.reset {
                let _ = reply.send(Err(DriverError::ClosedStream));
            } else {
                // 仍无数据：放回等待（不应发生，保守处理）
                state.pending_reply = Some(reply);
            }
        }
    }

    /// 轮询连接事件并推送给应用层
    fn poll_events(&mut self) {
        let handles: Vec<ConnectionHandle> = self.connections.keys().cloned().collect();
        let event_tx = self.event_tx.clone();

        for ch in handles {
            // 收集 accept 到的流（借用作用域独立，避免与后续读操作双重借用）
            let mut accepted: Vec<StreamId> = Vec::new();
            {
                if let Some(conn) = self.connections.get_mut(&ch) {
                    let mut streams = conn.streams();
                    while let Some(stream_id) = streams.accept(Dir::Uni) {
                        self.stream_route.insert(stream_id, ch);
                        accepted.push(stream_id);
                        tracing::debug!(?stream_id, "接受对端 uni-stream");
                    }
                    while let Some(stream_id) = streams.accept(Dir::Bi) {
                        self.stream_route.insert(stream_id, ch);
                        accepted.push(stream_id);
                        tracing::debug!(?stream_id, "接受对端 bi-stream");
                    }
                }
            }

            // 关键：quinn-proto 新流首批数据不触发 Readable 事件
            //（on_stream_frame 只置 opened 标志），accept 后必须主动读
            for stream_id in accepted {
                self.read_stream_into_buffer(ch, stream_id);
            }

            // 收集本连接的所有事件（先取事件再处理，避免双重可变借用）
            let mut events = Vec::new();
            {
                if let Some(conn) = self.connections.get_mut(&ch) {
                    while let Some(event) = conn.poll() {
                        events.push(event);
                    }
                }
            }
            for event in events {
                use quinn_proto::Event::*;
                match event {
                    HandshakeDataReady => {}
                    Connected => {
                        tracing::info!("QUIC 连接已建立");
                        let _ = event_tx.send(DriverEvent::Connected);
                    }
                    ConnectionLost { reason } => {
                        tracing::warn!(?reason, "连接丢失");
                        let _ = event_tx.send(DriverEvent::ConnectionLost {
                            reason: format!("{:?}", reason),
                        });
                    }
                    Stream(stream_event) => {
                        self.handle_stream_event(ch, stream_event);
                    }
                    DatagramReceived => {}
                    DatagramsUnblocked => {}
                }
            }
        }
    }

    /// 从连接读流数据入 per-stream 缓冲（accept 后主动读 + Readable 事件读共用）
    ///
    /// 根治 "too many gaps in stream buffer"（旧版每次只读一块，读取速度跟不上
    /// 到达速度 -> assembler 堆积超 1024 chunks -> 连接自杀）：
    /// 循环读尽当前可用数据（直到 Blocked），一次事件清空接收缓冲，
    /// 及时 finalize 释放流控窗口（MAX_STREAM_DATA 才能持续增长）。
    fn read_stream_into_buffer(&mut self, conn_handle: ConnectionHandle, id: StreamId) {
        // 单次事件最大读取量（4MB 防单流饿死其他流/事件循环）
        const MAX_EVENT_READ: usize = 4 * 1024 * 1024;

        // 循环读尽（限定借用作用域，避免与 stream_recv 双重可变借用）
        // 返回值：(本次读到的所有数据块, 是否读到 FIN)
        let (mut chunks_read, mut got_fin) = {
            let conn = match self.connections.get_mut(&conn_handle) {
                Some(c) => c,
                None => return,
            };
            let mut chunks_read: Vec<Vec<u8>> = Vec::new();
            let mut got_fin = false;
            let mut total = 0usize;

            loop {
                // 单块读取（Chunks 借用 recv_stream，借用收敛在函数内）
                let outcome = {
                    let mut recv_stream = conn.recv_stream(id);
                    let read_outcome = recv_stream.read(true);
                    let mut chunks = match read_outcome {
                        Ok(c) => c,
                        Err(_) => break, // 流不可读（已关闭等）
                    };
                    let chunk_outcome = chunks.next(STREAM_READ_CHUNK);
                    let result = match chunk_outcome {
                        Ok(Some(chunk)) => Ok(Some(chunk.bytes.to_vec())),
                        Ok(None) => Ok(None), // FIN
                        Err(_) => Err(()),    // Blocked（暂无数据）
                    };
                    let _ = chunks.finalize(); // 释放流控窗口
                    result
                };

                match outcome {
                    Ok(Some(data)) => {
                        total += data.len();
                        chunks_read.push(data);
                        if total >= MAX_EVENT_READ {
                            // 达到单次上限：剩余数据下次 Readable 事件再读
                            //（quinn-proto 会在还有未读数据时继续发 Readable）
                            break;
                        }
                    }
                    Ok(None) => {
                        // 流结束（FIN）
                        got_fin = true;
                        break;
                    }
                    Err(()) => {
                        // Blocked：当前可用数据已读尽
                        break;
                    }
                }
            }
            (chunks_read, got_fin)
        };

        // 数据入缓冲 + 回复挂起读取（先入缓冲再回复，reply 一次取走全部合并数据）
        if !chunks_read.is_empty() {
            // 合并为单个缓冲块（应用层一次 StreamRead 拿到全部，减少 channel 往返）
            let merged: Vec<u8> = if chunks_read.len() == 1 {
                chunks_read.pop().unwrap()
            } else {
                let total: usize = chunks_read.iter().map(|c| c.len()).sum();
                let mut merged = Vec::with_capacity(total);
                for c in chunks_read {
                    merged.extend_from_slice(&c);
                }
                merged
            };
            let data_len = merged.len();
            let state = self
                .stream_recv
                .entry(id)
                .or_insert_with(StreamRecvState::new);
            state.buffer.push_back(merged);
            // 回复挂起的读取请求（数据已就绪）
            self.flush_pending_reply(id);
            // 通知应用层：新数据可解析（TUIC 命令/转发数据）
            tracing::trace!(?id, len = data_len, "流数据入缓冲");
            let _ = self.event_tx.send(DriverEvent::StreamReadable { stream_id: id });
        }

        if got_fin {
            let state = self
                .stream_recv
                .entry(id)
                .or_insert_with(StreamRecvState::new);
            state.finished = true;
            self.flush_pending_reply(id);
            let _ = self.event_tx.send(DriverEvent::StreamFinished { stream_id: id });
        }
    }

    /// 处理流事件（v2 核心：Readable 时就地读取数据入缓冲并回复挂起的读取请求）
    fn handle_stream_event(&mut self, conn_handle: ConnectionHandle, event: quinn_proto::StreamEvent) {
        use quinn_proto::StreamEvent::*;
        let event_tx = self.event_tx.clone();

        match event {
            Opened { dir: _ } => {}
            Readable { id } => {
                // 后续数据到达（流已被 accept）：读入缓冲并通知应用层
                self.read_stream_into_buffer(conn_handle, id);
            }
            Writable { id } => {
                // 该流的流控窗口已释放（对端 MAX_STREAM_DATA 增长）：
                // 立即重试 pending_writes 中该流的阻塞写入。
                // 根治上传死锁：旧版此分支为空，Blocked 写入永远无人唤醒
                //（事件循环只在收包/请求/超时后才跑 retry_pending_writes，
                // 而流控窗口释放本身不产生新事件 -> select 永远挂起）。
                tracing::trace!(?id, "流可写事件，重试阻塞写入");
                self.retry_pending_writes();
            }
            Finished { id } => {
                let state = self
                    .stream_recv
                    .entry(id)
                    .or_insert_with(StreamRecvState::new);
                state.finished = true;
                self.flush_pending_reply(id);
                let _ = event_tx.send(DriverEvent::StreamFinished { stream_id: id });
            }
            Stopped { id, error_code } => {
                let state = self
                    .stream_recv
                    .entry(id)
                    .or_insert_with(StreamRecvState::new);
                state.reset = true;
                self.flush_pending_reply(id);
                let _ = event_tx.send(DriverEvent::StreamStopped {
                    stream_id: id,
                    error_code: error_code.into_inner(),
                });
            }
            Available { dir: _ } => {}
        }
    }

    /// 轮询 Endpoint 事件并路由到连接
    fn poll_endpoint_events(&mut self) {
        let handles: Vec<ConnectionHandle> = self.connections.keys().cloned().collect();

        for ch in handles {
            loop {
                let endpoint_event = {
                    if let Some(conn) = self.connections.get_mut(&ch) {
                        conn.poll_endpoint_events()
                    } else {
                        None
                    }
                };

                if let Some(event) = endpoint_event {
                    // Drained：endpoint 已移除该连接的 CID 索引，驱动同步清理 connections
                    // 条目（否则死连接条目永久泄漏，handle_request 路由到已关闭连接）
                    let drained = event.is_drained();
                    if let Some(conn_event) = self.endpoint.handle_event(ch, event) {
                        if drained {
                            self.connections.remove(&ch);
                            self.stream_route.retain(|_, h| *h != ch);
                            if self.conn_handle == Some(ch) {
                                self.conn_handle = None;
                            }
                            tracing::debug!(?ch, "连接已排空，清理驱动条目");
                        }
                        if let Some(conn) = self.connections.get_mut(&ch) {
                            conn.handle_event(conn_event);
                        }
                    }
                } else {
                    break;
                }
            }
        }
    }

    /// 重试 Blocked 的流写入（由 drain_and_flush 每轮驱动）
    fn retry_pending_writes(&mut self) {
        if self.pending_writes.is_empty() {
            return;
        }

        let mut retry_queue = std::mem::take(&mut self.pending_writes);
        let mut remaining = VecDeque::new();

        while let Some(mut pending) = retry_queue.pop_front() {
            let conn_handle = match self.stream_route.get(&pending.stream_id) {
                Some(ch) => *ch,
                None => {
                    // 路由丢失（连接已断）
                    if let Some(reply) = pending.reply.take() {
                        let _ = reply.send(Err(DriverError::NotConnected));
                    }
                    continue;
                }
            };

            let conn = match self.connections.get_mut(&conn_handle) {
                Some(c) => c,
                None => {
                    if let Some(reply) = pending.reply.take() {
                        let _ = reply.send(Err(DriverError::NotConnected));
                    }
                    continue;
                }
            };

            let mut send_stream = conn.send_stream(pending.stream_id);
            match send_stream.write(&pending.data) {
                Ok(n) => {
                    if let Some(reply) = pending.reply.take() {
                        let _ = reply.send(Ok(n));
                    }
                }
                Err(quinn_proto::WriteError::Blocked) => {
                    // 仍然阻塞，放回队列
                    remaining.push_back(pending);
                }
                Err(e) => {
                    if let Some(reply) = pending.reply.take() {
                        let _ = reply.send(Err(DriverError::Other(format!("重试写入失败: {}", e))));
                    }
                }
            }
        }

        self.pending_writes = remaining;
    }

    /// 发送所有待发包（从所有连接的 poll_transmit 取包，加密+套壳+非阻塞发送）
    ///
    /// 返回 true 表示至少发送了一个包（用于 drain 循环控制）。
    fn flush_sends(&mut self, _send_buf: &mut Vec<u8>) -> bool {
        let now = Instant::now();
        let handles: Vec<ConnectionHandle> = self.connections.keys().cloned().collect();
        let mut sent_any = false;

        for ch in handles {
            loop {
                // 优先重发 EAGAIN 排队的包（保证包序）
                if self.queued_packet.is_some() {
                    let still_blocked = {
                        let (transmit, quic_packet) = self.queued_packet.as_ref().unwrap();
                        let packet_data = &quic_packet[..transmit.size.min(quic_packet.len())];
                        // 借用冲突处理：clone 目标地址（SocketAddr 是 Copy 无冲突，
                        // 但 queued_packet 的不可变借用与 send_wire_packet 的 &mut self 冲突）
                        let dst = transmit.destination;
                        let data = packet_data.to_vec();
                        !self.send_wire_packet(&dst, &data)
                    };
                    if still_blocked {
                        self.send_blocked = true;
                        return sent_any;
                    } else {
                        self.queued_packet = None;
                        sent_any = true;
                    }
                }

                // 从连接获取待发送的 QUIC 包
                let transmit_result = {
                    let conn = match self.connections.get_mut(&ch) {
                        Some(c) => c,
                        None => break,
                    };
                    let mut buf = Vec::with_capacity(2048);
                    conn.poll_transmit(now, 1, &mut buf)
                        .map(|t| (t, buf))
                };

                let (transmit, quic_packet) = match transmit_result {
                    Some(r) => r,
                    None => break,
                };

                let packet_data = &quic_packet[..transmit.size.min(quic_packet.len())];
                if self.send_wire_packet(&transmit.destination, packet_data) {
                    sent_any = true;
                } else {
                    // EAGAIN：wmem 满。包重排队（QUIC 包不能丢），等 writable 事件。
                    self.queued_packet = Some((transmit, quic_packet));
                    self.send_blocked = true;
                    break;
                }
            }
            if self.send_blocked {
                break;
            }
        }

        sent_any
    }

    /// 加密 + 套 RTP 壳 + 非阻塞发送一个 wire 包
    ///
    /// 载荷格式：[8B 包号 BE][AES-128-CTR 密文]
    /// - 包号前缀让接收方恢复 AES nonce（[连接前缀][包号]，见 crypto.rs）
    /// - RTP 头 12B：V=2 首字节 0x80，PT=96，SEQ 连续 +1，TS 按 90000Hz 30fps
    ///   节奏（每 2 包一帧），SSRC 连接级固定 → DPI 识别为 RTP 视频流
    /// - 变长直发（贴近 quinn/TUIC 原生流控，ACK 小包不放大，带宽最优）
    fn send_wire_packet(&mut self, dst: &SocketAddr, quic_packet: &[u8]) -> bool {
        // 1. AES 加密（包号嵌入 RTP 载荷前缀供接收方解密）
        let (ciphertext, packet_num) = self.cipher.encrypt(quic_packet);

        // 2. 载荷：[8B 包号 BE][密文]
        let mut payload = Vec::with_capacity(RTP_PKTNUM_LEN + ciphertext.len());
        payload.extend_from_slice(&packet_num.to_be_bytes());
        payload.extend_from_slice(&ciphertext);

        // 3. 套 RTP 外壳（SEQ 连续 +1、SSRC 固定，视频节奏）
        self.srt_seq = self.srt_seq.wrapping_add(1);
        let rtp_packet = RtpPacket::data(self.srt_seq as u16, self.rtp_ssrc, payload);
        let wire_data = rtp_packet.encode();

        // 4. 周期注入 RTCP Sender Report（真实视频会话标配控制通道）。
        //    简化 DPI（如爱快/OpenWrt 面板）常要求 RTP+RTCP 成对才识别为视频流。
        //    每 500ms 在数据包之间夹一个 SR 包（SSRC 与 RTP 一致，模拟真实发送统计）。
        let now = Instant::now();
        if self.last_rtcp_at.map_or(true, |t| now.duration_since(t) >= Duration::from_millis(500)) {
            self.last_rtcp_at = Some(now);
            self.rtcp_pkt_count = self.rtcp_pkt_count.wrapping_add(1);
            self.rtcp_octet_count = self.rtcp_octet_count.wrapping_add(wire_data.len() as u32);
            let sr = crate::transport::rtp_shell::build_rtcp_sr(
                self.rtp_ssrc,
                rtp_packet.timestamp,
                self.rtcp_pkt_count,
                self.rtcp_octet_count,
            );
            // RTCP 用独立 UDP 包发送（不占 RTP 序号，nDPI 会识别为 RTCP 通道）
            let _ = self.socket.try_send_to(&sr, *dst);
        }

        // 5. 非阻塞发送（EAGAIN 返回 false，绝不阻塞 driver）
        match self.socket.try_send_to(&wire_data, *dst) {
            Ok(_) => true,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // 被信号中断，视为发送失败但不置位 blocked（下轮重试）
                false
            }
            Err(e) => {
                // 真错误（如网络不可达）：记录但不中断循环
                tracing::warn!(error = %e, "UDP 发送失败");
                true
            }
        }
    }

    /// 重发 EAGAIN 时排队的 QUIC 包（writable 事件后调用）
    fn retry_queued_packet(&mut self) {
        if let Some((transmit, quic_packet)) = self.queued_packet.take() {
            let packet_data = &quic_packet[..transmit.size.min(quic_packet.len())];
            if !self.send_wire_packet(&transmit.destination, packet_data) {
                // 仍然 EAGAIN：放回队列继续等 writable
                self.queued_packet = Some((transmit, quic_packet));
                self.send_blocked = true;
            }
        }
    }

    /// 回复错误
    fn reply_error(&self, req: DriverRequest, err: DriverError) {
        match req {
            DriverRequest::OpenBiStream { reply } => {
                let _ = reply.send(Err(err));
            }
            DriverRequest::StreamWrite { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            DriverRequest::StreamFinish { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            DriverRequest::StreamReset { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            DriverRequest::StreamStop { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            DriverRequest::StreamRead { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            DriverRequest::SendUniStream { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            DriverRequest::Close { reply } => {
                let _ = reply.send(());
            }
            DriverRequest::ExportKeyingMaterial { reply, .. } => {
                let _ = reply.send(Err(err));
            }
        }
    }
}

/// 构建传输配置（客户端/服务端共用）
///
/// 关键修复：
/// - mtu_discovery_config(None)：禁用 MTU 探测（"too many gaps" 根因）
/// - initial_mtu=1200：QUIC 包最大 1200B + 12B RTP 头 = 1212B wire，
///   以太网 MTU 1500 内不分片
/// v0.4.3 优化：窗口从 10M->32M/8M，提升高 RTT 链路带宽（本地 52->50MB/s 保量，公网 40ms RTT 下 BDP 需大窗口）
fn build_transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    config
        .max_concurrent_bidi_streams(VarInt::from_u32(256))
        .max_concurrent_uni_streams(VarInt::from_u32(256))
        .max_idle_timeout(Some(
            quinn_proto::IdleTimeout::try_from(Duration::from_secs(60)).unwrap(),
        ))
        .send_window(32 * 1024 * 1024)
        .receive_window(VarInt::from_u32(32 * 1024 * 1024))
        .stream_receive_window(VarInt::from_u32(8 * 1024 * 1024))
        // 禁用 MTU 探测（回环 MTU 65536 会探测出巨型包导致对端接收截断）
        .mtu_discovery_config(None)
        .initial_mtu(1200)
        .min_mtu(1200);
    config
}

/// 跳过 TLS 证书验证（QUIC 明文已被 AES 加密覆盖，认证由 TUIC 协议保证）
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
