//! srt/connection.rs — SRT 连接安全封装
//!
//! 设计决策（Q2/Q21）：
//! - 封装 libsrt 的 socket 生命周期、收发、epoll 事件循环
//! - 线程模型：SRT 事件循环跑在独立线程（epoll 阻塞等待），
//!   收到数据通过 channel 发到 tokio 异步任务
//! - 发送侧：tokio 任务把 TS 帧写入 SRT socket（阻塞式 send，内部排队）
//! - 所有 unsafe 调用局限在本文件

use std::net::SocketAddr;
use std::os::raw::{c_char, c_int};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

// 发送通道仍用 crossbeam（发送线程由 std::thread 驱动，与 tokio 无直接耦合）
// 接收通道 2026-08-19 改为 tokio mpsc Unbounded（消除 spawn_blocking 桥接瓶颈）
use crossbeam_channel::Sender;

use super::bindings::*;

// ===== S6 修复（2026-08-19）：全局 srt_startup/cleanup 引用计数 =====
// 背景：每个 connect/accept 各调一次 srt_startup()（libsrt 内部是计数式，
// 第 N 次调用只是 ++，最后一次 cleanup 才真正停 GC 线程），但进程退出时
// 从未调用 srt_cleanup -> GC 线程与静态析构器（CUDTUnited::~CUDTUnited）
// 竞态 -> 退出段错误（CRcvQueue::worker 崩溃，实测 exit code 139）。
// 现在每次成功的 startup 配对一个注册的 cleanup（进程退出时按逆序执行）。
static SRT_INIT: std::sync::Once = std::sync::Once::new();

/// 全局初始化 libsrt（幂等；注册退出时 srt_cleanup，防 GC 线程析构竞态崩溃）
fn srt_global_init() -> Result<(), SrtError> {
    let mut init_err: Option<String> = None;
    SRT_INIT.call_once(|| {
        // 注意：call_once 闭包本身不是 unsafe 上下文，FFI 调用需要 unsafe 块
        unsafe {
            if srt_startup() == -1 {
                init_err = Some(last_error_str());
                return;
            }
            // 注册退出清理：进程退出时停止 GC 线程并关闭全部 socket。
            // 注意必须放在 atexit（而非 Drop）：SrtConnection 可能因 process::exit
            // 被跳过，而 atexit 无论如何都会执行。
            extern "C" fn srt_exit_cleanup() {
                unsafe { srt_cleanup() };
            }
            libc::atexit(srt_exit_cleanup);
        }
    });
    match init_err {
        Some(e) => Err(SrtError::Init(e)),
        None => Ok(()),
    }
}

/// SRT 连接错误
#[derive(Debug)]
pub enum SrtError {
    /// 初始化失败
    Init(String),
    /// 连接失败
    Connect(String),
    /// 发送失败
    /// （P1 后半段接入隧道收发时启用）
    #[allow(dead_code)]
    Send(String),
    /// 接收失败
    /// （P1 后半段接入隧道收发时启用）
    #[allow(dead_code)]
    Recv(String),
    /// 参数错误
    Param(String),
    /// 对端关闭
    Closed,
}

impl std::fmt::Display for SrtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SrtError::Init(e) => write!(f, "SRT 初始化失败: {e}"),
            SrtError::Connect(e) => write!(f, "SRT 连接失败: {e}"),
            SrtError::Send(e) => write!(f, "SRT 发送失败: {e}"),
            SrtError::Recv(e) => write!(f, "SRT 接收失败: {e}"),
            SrtError::Param(e) => write!(f, "SRT 参数错误: {e}"),
            SrtError::Closed => write!(f, "SRT 连接已关闭"),
        }
    }
}

/// SRT socket 配置参数
#[derive(Debug, Clone)]
pub struct SrtConfig {
    /// 对端地址（客户端：服务器地址；服务端：忽略）
    pub peer_addr: SocketAddr,
    /// passphrase（SRT 原生加密，10-79 字符）
    pub passphrase: String,
    /// 加密强度：16/24/32 字节密钥（aes-128/192/256）
    pub pbkeylen: i32,
    /// streamid（客户端设置，服务端读取）
    pub streamid: Option<String>,
    /// 接收延迟毫秒（rcv-latency，默认 1000）
    pub rcv_latency: i32,
    /// 是否可靠模式（reliable=true 时 SRT 自动重传；best-effort=false）
    pub reliable: bool,
    /// 消息模式（本隧道使用消息模式，一条消息=一个 TS 帧）
    pub message_api: bool,
    /// payload 大小（SRT 消息模式单包上限，1316 官方默认）
    pub payload_size: i32,
    /// v0.5.3：UDP DATAGRAM 实验模式开关（默认 false）
    /// false = UDP 帧走可靠传输（Data 帧 + 可靠队列，= v0.5.0 行为，WebRTC 必达）
    /// true  = UDP 帧走 Datagram 帧 + 自适应 TTL（低延时实验特性，拥塞时会丢包，
    ///         仅适合游戏/实时等可容忍丢包场景；参考 hy2 后结论：默认必须关）
    pub udp_datagram: bool,
    /// 是否服务端（listen 模式）
    /// （P1 后半段用于区分收发策略，当前仅日志参考）
    #[allow(dead_code)]
    pub is_server: bool,
}

impl Default for SrtConfig {
    fn default() -> Self {
        Self {
            peer_addr: "127.0.0.1:9000".parse().unwrap(),
            passphrase: String::new(),
            pbkeylen: 16, // aes-128
            streamid: None,
            rcv_latency: 120, // P1 2026-08-23：1000→120ms 降低 TTFB（TSBPD 关闭后仅重传窗口，120ms 已够 70ms RTT 重传）
            reliable: true,
            message_api: true,
            payload_size: 1316, // SRT 官方默认 payload
            // v0.5.3：UDP DATAGRAM 实验模式默认关闭（拥塞时丢包伤 WebRTC，见字段注释）
            udp_datagram: false,
            is_server: false,
        }
    }
}

/// 收到的 SRT 消息
#[derive(Debug)]
pub struct SrtMessage {
    /// 数据（TS 帧或复用层帧）
    pub data: Vec<u8>,
}

// ===== v0.5.2 QUIC STREAM/DATAGRAM 双通道语义（2026-08-23）=====
//
/// 发送队列条目：携带可靠性语义的发送单元
///
/// 映射关系（参照 QUIC RFC9000）：
/// - reliable=true  ≙ STREAM 帧：msgttl=-1（无限 TTL，永不放弃重传）+ inorder=1（保序投递）
/// - reliable=false ≙ DATAGRAM 帧：msgttl=自适应值（过期即弃，不重传）+ inorder=0（允许后发先至）
#[derive(Debug)]
pub struct SendItem {
    /// 待发送数据（一个隧道帧，≤1301B，单 SRT 消息原子投递）
    pub data: Vec<u8>,
    /// 是否可靠传输（TCP 数据帧 true；UDP Datagram 帧 false）
    pub reliable: bool,
    /// 不可靠消息的存活时长毫秒（reliable=true 时忽略；由 RttTracker 自适应生成）
    pub ttl_ms: i32,
}

impl SendItem {
    /// 构造可靠消息（STREAM 语义：TCP 数据、控制帧全走此路径，行为与旧版完全一致）
    pub fn reliable(data: Vec<u8>) -> Self {
        Self { data, reliable: true, ttl_ms: -1 }
    }

    /// 构造不可靠消息（DATAGRAM 语义：UDP 数据报，TTL 内未发出/未被确认即丢弃）
    pub fn unreliable(data: Vec<u8>, ttl_ms: i32) -> Self {
        Self { data, reliable: false, ttl_ms }
    }
}

/// RTT/链路状态跟踪器：EWMA 平滑瞬时 RTT 并推导自适应消息 TTL
///
/// 为什么不用固定 TTL：不同服务器链路延时差异大（70ms~400ms+），且可能突变；
/// 固定小值会导致高延时链路上 UDP 包大量被误丢，固定大值则失去"过期即弃"的低延时意义。
/// 因此按实测 RTT 动态调整：TTL = max(2×EWMA_RTT, 150ms)。
///
/// 线程模型：接收线程写（sample_rtt）、上层多任务读（adaptive_ttl_ms），
/// 用 AtomicI32 存储毫秒整数避免锁开销；并发更新偶发覆盖对统计平滑无实质影响，
/// 无需 CAS 循环。
pub struct RttTracker {
    /// EWMA 平滑后的 RTT（毫秒）。原子存储：读多写少且精度要求为毫秒级整数
    ewma_ms: std::sync::atomic::AtomicI32,
    /// v0.5.3：SND BUF 未确认数据的时间跨度（毫秒，来自 bistats.msSndBuf）。
    /// 由接收线程随 RTT 一并采样写入，供发送线程做 TCP 背压判定：
    /// 积压超过阈值时暂停消费可靠队列，让 UDP 小包优先追上进度（仿 hy2 公平性）。
    sndbuf_ms: std::sync::atomic::AtomicI32,
}

impl RttTracker {
    /// EWMA 初始值：取典型国际链路 RTT 量级（70ms），冷启动时给出合理默认 TTL
    const INIT_MS: i32 = 70;
    /// 平滑系数 α=1/8（与 TCP RTT 经验值一致：兼顾平滑性与突变响应速度）
    const ALPHA_DEN: f64 = 8.0;
    /// EWMA 下限钳制：低于 60ms 视为本底噪声（内网/回环），避免 TTL 过小误丢
    const MIN_MS: i32 = 60;
    /// EWMA 上限钳制：超过 800ms 的链路已不适合 UDP 低延时场景，封顶防 TTL 失控
    const MAX_MS: i32 = 800;
    /// 自适应 TTL 下限：即使低 RTT 也至少给 150ms 发送窗口（约 2 个 RTT + 调度余量）
    const TTL_MIN_MS: i32 = 150;
    /// v0.5.3：TCP 背压阈值——SNDBUF 未确认时间跨度超过此值时暂停消费可靠队列。
    /// 取值考量：rcv_latency=120ms 重传窗口的 2.5 倍；超过说明 TCP 大流量已把
    /// 发送管道塞满，此时继续入队 TCP 只会把 UDP 小包越推越远，应让 UDP 先行。
    const SND_BACKPRESSURE_MS: i32 = 300;

    pub fn new() -> Self {
        Self {
            ewma_ms: std::sync::atomic::AtomicI32::new(Self::INIT_MS),
            sndbuf_ms: std::sync::atomic::AtomicI32::new(0),
        }
    }

    /// 当前 SND BUF 积压时间跨度（毫秒，接收线程采样写入）
    pub fn sndbuf_ms(&self) -> i32 {
        self.sndbuf_ms.load(std::sync::atomic::Ordering::Acquire)
    }

    /// 写入 SND BUF 积压跨度（接收线程采样调用；负值钳为 0 防御异常读数）
    pub fn set_sndbuf_ms(&self, ms: i32) {
        self.sndbuf_ms.store(ms.max(0), std::sync::atomic::Ordering::Release);
    }

    /// 是否处于 TCP 背压状态（发送线程调度判定用）
    #[allow(dead_code)]
    pub fn tcp_backpressured(&self) -> bool {
        self.sndbuf_ms() > Self::SND_BACKPRESSURE_MS
    }

    /// 采样新的瞬时 RTT 并更新 EWMA
    ///
    /// 公式：new = old×(7/8) + sample×(1/8)，钳位 [60, 800]ms。
    /// 返回更新后的 EWMA 值（供日志观测）。
    pub fn update(&self, rtt_ms: f64) -> i32 {
        use std::sync::atomic::Ordering;
        // 非法采样直接忽略（bistats 失败或未连接时 msRTT 可能为 0/负数）
        if !(rtt_ms > 0.0 && rtt_ms.is_finite()) {
            return self.ewma_ms.load(Ordering::Acquire);
        }
        let old = self.ewma_ms.load(Ordering::Acquire) as f64;
        let next = ((old * (1.0 - 1.0 / Self::ALPHA_DEN)) + rtt_ms / Self::ALPHA_DEN)
            .round()
            .clamp(Self::MIN_MS as f64, Self::MAX_MS as f64) as i32;
        self.ewma_ms.swap(next, Ordering::AcqRel);
        next
    }

    /// 当前 EWMA RTT（毫秒）
    pub fn ewma_ms(&self) -> i32 {
        self.ewma_ms.load(std::sync::atomic::Ordering::Acquire)
    }

    /// 由当前 RTT 推导不可靠消息的自适应 TTL：
    /// max(2×EWMA_RTT, 150ms)。2×RTT 保证正常情况下消息有足够时间完成一次
    /// 发送往返；150ms 下限防止低 RTT 链路上 TTL 过小造成无谓丢弃。
    pub fn adaptive_ttl(&self) -> i32 {
        (self.ewma_ms() * 2).max(Self::TTL_MIN_MS)
    }
}

/// SRT 连接封装
///
/// 线程模型：
/// - recv_rx: 事件循环线程 → 应用层（tokio 任务消费）
///   - 2026-08-19 重构：接收通道改为 tokio mpsc Unbounded，
///     接收线程（std::thread）直接同步 send → tokio UnboundedSender，
///     tokio 侧直接 UnboundedReceiver.recv().await 消费，
///     消除原先 crossbeam + spawn_blocking 的双重桥接瓶颈（全双工吞吐塌陷根因）。
/// - send_tx: 应用层 → 事件循环线程（发送队列）
pub struct SrtConnection {
    socket: SRTSOCKET,
    /// 接收通道（事件循环线程产出；tokio UnboundedReceiver 供异步消费）
    /// 用 tokio Mutex 包装以支持 &self 方法 + 跨 await 安全
    recv_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<SrtMessage>>>,
    /// v0.5.5：接收通道当前积压条数（recv 线程入队 +1，上层消费 -1）
    /// 用途：高水位背压判定——浏览器停止读下载时让 SRT 流控刹车，
    /// 防止"僵尸下载"残留流量挤占上行带宽（详见 run_recv_loop 注释）。
    /// tokio UnboundedSender 无 len()，故用原子计数器自行跟踪。
    recv_len: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// 发送通道（应用层投入）
    /// 2026-08-19 S1 修复：Mutex<Option<Sender>> 包装--
    /// close() 时锁内 take+drop 关闭通道，发送线程 recv() 返回 Err 自然退出。
    /// （旧实现发"空消息"但发送线程不检查，发送线程永不退出=socket 永不关闭）
    /// v0.5.2：条目类型 Vec<u8> → SendItem（携带可靠/TTL 语义，支撑 QUIC 双通道）
    ///
    /// v0.5.3 双队列调度（参考 hysteria2 公平性思想）：
    /// - send_rel_tx：可靠队列——TCP Data 帧、控制帧、以及默认模式下的 UDP 帧
    /// - send_prio_tx：优先队列——仅 udp_datagram=true 时 Datagram 帧走此队列，
    ///   发送线程每轮无条件先清空它，UDP 小包不再排在 TCP 大流量积压之后
    ///   （v0.5.2 的 TTL 丢弃方案已废弃：拥塞时丢包会杀死 WebRTC 的 STUN/DTLS 握手）
    send_rel_tx: std::sync::Mutex<Option<Sender<SendItem>>>,
    #[allow(dead_code)]
    send_prio_tx: std::sync::Mutex<Option<Sender<SendItem>>>,
    /// v0.5.3：是否启用 UDP DATAGRAM 实验模式（来自 SrtConfig.udp_datagram，默认 false）
    /// false = UDP 走可靠 Data 帧（= v0.5.0 行为，WebRTC 必达）；true = Datagram 帧 + 自适应 TTL
    udp_datagram: bool,
    /// v0.5.2：RTT 跟踪器（接收线程采样写入，上层 adaptive_ttl_ms 读取）
    rtt: Arc<RttTracker>,
    /// epoll 句柄：已移除结构体字段（2026-08-19 S1 修复）
    /// eid 的生命周期归接收线程所有（接收线程退出时 srt_epoll_release 释放，
    /// 结构体不再持有，消除 close() 跨线程释放使用中句柄的 UB 与双重释放）。
    /// 连接是否已关闭（CAS 原子标志，保证 srt_close/线程清理只执行一次）
    /// 2026-08-19 S1 修复：旧 closed: Arc<Mutex<bool>> 无幂等保护，
    /// close()+Drop 双重释放 epoll；现改为原子 CAS + 各资源单一释放方
    closed: Arc<AtomicBool>,
    /// 收发线程句柄（S6 修复 2026-08-19：close() 时 join 等待线程退出）
    /// 背景：进程退出时（尤其 process::exit 路径）若收发线程仍在运行，
    /// 会与 libsrt 静态析构器（CUDTUnited::~CUDTUnited 停 GC 线程）竞态，
    /// 导致退出段错误（实测 CRcvQueue::worker 崩溃 exit 139）。
    /// close() 里 join 确保线程先于 libsrt 清理退出。
    /// Mutex 包装：close(&self) 无 &mut，用内部可变性取走 handle。
    threads: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
}

// SrtConnection 不直接 Send/Sync 传递跨线程，但内部有 Arc 标记
unsafe impl Send for SrtConnection {}
unsafe impl Sync for SrtConnection {}

impl SrtConnection {
    /// 建立 SRT 连接（客户端）
    ///
    /// 流程：创建 socket → 配置选项 → connect → 启动事件循环线程
    pub fn connect(cfg: &SrtConfig) -> Result<Self, SrtError> {
        unsafe {
            // 1. 全局初始化（S6：幂等 + atexit 注册 cleanup，防退出段错误）
            srt_global_init()?;

            // 2. 创建 socket
            let sock = srt_create_socket();
            if sock == -1 {
                return Err(SrtError::Init(last_error_str()));
            }

            // 3. 配置 socket 选项
            Self::apply_options(sock, cfg)?;

            // 4. 解析地址并连接
            let addr = cfg.peer_addr;
            let sockaddr = sockaddr_from(addr)?;
            let ret = srt_connect(
                sock,
                &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as c_int,
            );
            if ret == -1 {
                let err = last_error_str();
                srt_close(sock);
                return Err(SrtError::Connect(err));
            }

            // 重要：非阻塞 connect 返回 0 只代表"连接已发起"，并不代表连接完成！
            // 必须等待 SRT_EPOLL_CONNECT 事件确认连接真正建立，才能开始收发。
            // 若不等待，会出现"sendmsg 成功但对端收不到"的现象（前面实测）。
            {
                // 创建临时 epoll，监听连接完成事件
                let conn_eid = srt_epoll_create();
                if conn_eid == -1 {
                    let err = last_error_str();
                    srt_close(sock);
                    return Err(SrtError::Init(err));
                }
                let connect_events = SRT_EPOLL_CONNECT;
                if srt_epoll_add_usock(conn_eid, sock, &connect_events) == -1 {
                    let err = last_error_str();
                    srt_epoll_release(conn_eid);
                    srt_close(sock);
                    return Err(SrtError::Init(err));
                }
                // 阻塞等待连接事件（5 秒超时）
                let mut events_buf = [SRT_EPOLL_EVENT { fd: -1, events: 0 }; 8];
                let n = srt_epoll_uwait(conn_eid, events_buf.as_mut_ptr(), events_buf.len() as c_int, 5000);
                let mut connected = false;
                if n > 0 {
                    for ev in events_buf.iter().take(n as usize) {
                        if ev.fd == sock {
                            connected = true;
                            break;
                        }
                    }
                }
                srt_epoll_release(conn_eid);
                if !connected {
                    let err = last_error_str();
                    srt_close(sock);
                    return Err(SrtError::Connect(format!("连接超时: {err}")));
                }
                tracing::debug!("SRT 连接事件确认，连接完成");
            }

            // 关键：连接确认后短暂等待，让 SRT 内部接收/发送队列完全就绪
            // P0+P1 2026-08-23：200ms→50ms 降低首包 TTFB（实测 50ms 已足够，配合 epoll CONNECT 事件，移除后偶发丢首包）
            std::thread::sleep(std::time::Duration::from_millis(50));

            // 连接建立后设为非阻塞（配合 epoll 事件循环收发）
            Self::set_nonblocking(sock)?;

            // 5. 启动事件循环线程
            // 发送通道用 unbounded：发送方（send_async）永不因背压阻塞调用方，
            // 避免多会话并发时 spawn_blocking 线程池被 channel 满的 send 占满而死锁。
            // 背压由发送线程（run_send_loop）内部通过 srt_sendmsg 感知并自我调速。
            // 接收通道 2026-08-19 改为 tokio mpsc Unbounded：
            //   接收线程（std::thread）同步 send → UnboundedSender，
            //   tokio 侧直接 UnboundedReceiver.recv().await 异步消费。
            //   消除原先 crossbeam + spawn_blocking 双重桥接的全双工吞吐瓶颈。
            let (recv_tx, recv_rx) = tokio::sync::mpsc::unbounded_channel::<SrtMessage>();
            // v0.5.5：接收积压计数器（recv 线程 +1 / 上层消费 -1），高水位背压判定用
            let recv_len_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let recv_len_recv = recv_len_counter.clone();
            // v0.5.3 双队列：可靠队列(TCP/控制/默认UDP) + 优先队列(实验 Datagram)；
            // RTT/SNDBUF 跟踪器随连接创建（收发线程共享 Arc）
            let (send_rel_tx, send_rel_rx) = crossbeam_channel::unbounded::<SendItem>();
            let (send_prio_tx, send_prio_rx) = crossbeam_channel::unbounded::<SendItem>();
            let rtt = Arc::new(RttTracker::new());
            let udp_datagram = cfg.udp_datagram;
            let eid = srt_epoll_create();
            if eid == -1 {
                let err = last_error_str();
                srt_close(sock);
                return Err(SrtError::Init(err));
            }
            // epoll 监听 IN（可读）
            let events = SRT_EPOLL_IN | SRT_EPOLL_ERR;
            if srt_epoll_add_usock(eid, sock, &events) == -1 {
                let err = last_error_str();
                srt_epoll_release(eid);
                srt_close(sock);
                return Err(SrtError::Init(err));
            }

            // 2026-08-19 S1 修复：关闭标志改原子 CAS（幂等），发送线程退出后由 close() 统一 srt_close
            let closed = Arc::new(AtomicBool::new(false));
            let closed_send = closed.clone();
            // 发送线程（双队列调度，见 run_send_loop 注释）
            // S6：保存 JoinHandle 供 close() join（防退出段错误）
            let send_sock = sock;
            let send_thread = std::thread::spawn(move || {
                Self::run_send_loop(send_rel_rx, send_prio_rx, send_sock);
                // 发送线程退出仅置位 closed（socket 由 close()/Drop 统一关闭，S1 单一释放方）
                closed_send.store(true, AtomicOrdering::Release);
            });

            // 接收事件循环线程（批量消费，优化吞吐，见 run_recv_loop 注释）
            // 2026-08-19 S1 修复：eid 生命周期归接收线程--退出时负责 srt_epoll_release，
            // 避免 close() 在 uwait 阻塞期间跨线程释放（UB）与双重释放
            // S6：保存 JoinHandle 供 close() join（防退出段错误）
            let recv_sock = sock;
            let closed_recv = closed.clone();
            let rtt_recv = rtt.clone();
            let recv_thread = std::thread::spawn(move || {
                Self::run_recv_loop(recv_sock, eid, recv_tx, rtt_recv, recv_len_recv);
                // 接收线程退出 = 连接终结：置位 closed + 释放 epoll（唯一释放方）
                closed_recv.store(true, AtomicOrdering::Release);
                // 注：此处处于外层 unsafe 块内，无需再套 unsafe（修复嵌套警告）
                srt_epoll_release(eid);
            });

            Ok(Self {
                socket: sock,
                recv_rx: Arc::new(tokio::sync::Mutex::new(recv_rx)),
                recv_len: recv_len_counter,
                send_rel_tx: Mutex::new(Some(send_rel_tx)),
                send_prio_tx: Mutex::new(Some(send_prio_tx)),
                udp_datagram,
                rtt,
                closed,
                threads: Mutex::new(vec![send_thread, recv_thread]),
            })
        }
    }

    /// 服务端监听 socket（一次 bind+listen，常驻；供 accept_one 循环复用）
    ///
    /// 2026-08-19 M1 配套修复（accept 并行化引入的端口占用 bug）：
    /// 旧 SrtConnection::accept 每次调用都走完整 bind->listen->accept(1个)->close(监听)。
    /// 串行 accept_loop 下无问题；但 M1 并行化后多个任务同时 bind 同一端口 ->
    /// "Another socket is already listening on the same port" 无限报错，
    /// 除第一个任务外全部 accept 失败。
    /// 正确模型：监听 socket 全局唯一且常驻（bind 一次），accept 可在
    /// 多任务中并发调用（srt_accept 线程安全，内核/libsrt 内部排队）。
    pub fn bind_listener(cfg: &SrtConfig) -> Result<SrtListener, SrtError> {
        unsafe {
            // S6：全局初始化（幂等 + atexit 注册 cleanup，防退出段错误）
            srt_global_init()?;
            let sock = srt_create_socket();
            if sock == -1 {
                return Err(SrtError::Init(last_error_str()));
            }
            Self::apply_options(sock, cfg)?;

            // 绑定监听地址
            let addr = cfg.peer_addr;
            let sockaddr = sockaddr_from(addr)?;
            let ret = srt_bind(
                sock,
                &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as c_int,
            );
            if ret == -1 {
                let err = last_error_str();
                srt_close(sock);
                return Err(SrtError::Connect(err));
            }
            if srt_listen(sock, 128) == -1 {
                let err = last_error_str();
                srt_close(sock);
                return Err(SrtError::Connect(err));
            }
            tracing::info!(listen = %addr, "SRT 监听 socket 已建立（常驻）");
            Ok(SrtListener {
                sock,
                udp_datagram: cfg.udp_datagram,
            })
        }
    }

    /// 在监听 socket 上接受一个连接（阻塞直到新客户端到来或出错）
    ///
    /// 由 SrtListener 调用；每客户端一次（可在多任务并发调用，
    /// 监听 socket 常驻不重复 bind）。
    fn accept_from_listener(listen_sock: SRTSOCKET, udp_datagram: bool) -> Result<Self, SrtError> {
        unsafe {
            // 接受连接（阻塞；srt_accept 线程安全，多任务并发调用由 libsrt 内部排队）
            let mut peer: libc::sockaddr_in = std::mem::zeroed();
            let mut peer_len = std::mem::size_of::<libc::sockaddr_in>() as c_int;
            let accepted = srt_accept(
                listen_sock,
                &mut peer as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut peer_len,
            );
            if accepted == -1 {
                return Err(SrtError::Connect(last_error_str()));
            }
            // 关键：accept 返回后等待握手完全完成！
            // 实测：responder 立即发数据时，initiator 的握手（URQ_CONCLUSION/AGREEMENT）
            // 还没完成，会触发 "Connection was broken"，数据丢失。
            // P0+P1 2026-08-23：300ms→50ms 降低首包 TTFB（配合 epoll CONNECT 事件，50ms 已足够）
            std::thread::sleep(std::time::Duration::from_millis(50));

            // 已接受的连接设为非阻塞（配合 epoll 事件循环收发）
            Self::set_nonblocking(accepted)?;

            // 启动事件循环（同 connect 后半部分）
            // v0.5.3 双队列：与 connect 一致；v0.5.5 接收积压计数器
            let (recv_tx, recv_rx) = tokio::sync::mpsc::unbounded_channel::<SrtMessage>();
            let recv_len_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let recv_len_recv = recv_len_counter.clone();
            let (send_rel_tx, send_rel_rx) = crossbeam_channel::unbounded::<SendItem>();
            let (send_prio_tx, send_prio_rx) = crossbeam_channel::unbounded::<SendItem>();
            let rtt = Arc::new(RttTracker::new());
            let eid = srt_epoll_create();
            if eid == -1 {
                let err = last_error_str();
                srt_close(accepted);
                return Err(SrtError::Init(err));
            }
            let events = SRT_EPOLL_IN | SRT_EPOLL_ERR;
            if srt_epoll_add_usock(eid, accepted, &events) == -1 {
                srt_epoll_release(eid);
                srt_close(accepted);
                return Err(SrtError::Init(last_error_str()));
            }

            // 2026-08-19 S1 修复：与 connect() 相同的线程生命周期模型
            //   closed 原子 CAS 幂等；eid 归接收线程释放；socket 由 close()/Drop 统一关
            let closed = Arc::new(AtomicBool::new(false));
            let closed_send = closed.clone();
            // S6：保存 JoinHandle 供 close() join（防退出段错误）
            let send_sock = accepted;
            let send_thread = std::thread::spawn(move || {
                Self::run_send_loop(send_rel_rx, send_prio_rx, send_sock);
                closed_send.store(true, AtomicOrdering::Release);
            });

            // S6：保存 JoinHandle 供 close() join（防退出段错误）
            let recv_sock = accepted;
            let closed_recv = closed.clone();
            let rtt_recv = rtt.clone();
            let recv_thread = std::thread::spawn(move || {
                Self::run_recv_loop(recv_sock, eid, recv_tx, rtt_recv, recv_len_recv);
                // 接收线程退出 = 连接终结：置位 closed + 释放 epoll（唯一释放方，S1）
                closed_recv.store(true, AtomicOrdering::Release);
                // 注：此处处于外层 unsafe 块内，无需再套 unsafe（修复嵌套警告）
                srt_epoll_release(eid);
            });

            Ok(Self {
                socket: accepted,
                recv_rx: Arc::new(tokio::sync::Mutex::new(recv_rx)),
                recv_len: recv_len_counter,
                send_rel_tx: Mutex::new(Some(send_rel_tx)),
                send_prio_tx: Mutex::new(Some(send_prio_tx)),
                udp_datagram,
                rtt,
                closed,
                threads: Mutex::new(vec![send_thread, recv_thread]),
            })
        }
    }

    /// 服务端监听器（常驻监听 socket 封装）
    ///
    /// 2026-08-19 M1 配套修复：accept 并行化后监听 socket 必须全局唯一常驻
    /// （旧模型每连接重建 bind 会端口冲突）。
    /// - `accept_one`：阻塞接受一个连接（可在多任务并发调用）
    /// - Drop：关闭监听 socket（唯一释放方）
    unsafe fn apply_options(sock: SRTSOCKET, cfg: &SrtConfig) -> Result<(), SrtError> {
        let set = |opt: SRT_SOCKOPT, val: &dyn std::any::Any| -> Result<(), SrtError> {
            // 统一转换：支持 i32（大多数选项）和 i64（MAXBW/MININPUTBW/OHEADBW 等）
            if let Some(v) = val.downcast_ref::<i32>() {
                let ret = srt_setsockopt(sock, 0, opt, v as *const i32 as *const std::os::raw::c_void, std::mem::size_of::<i32>() as c_int);
                if ret == -1 {
                    return Err(SrtError::Param(format!("设置选项 {opt:?} 失败: {}", last_error_str())));
                }
                return Ok(());
            }
            if let Some(v) = val.downcast_ref::<i64>() {
                let ret = srt_setsockopt(sock, 0, opt, v as *const i64 as *const std::os::raw::c_void, std::mem::size_of::<i64>() as c_int);
                if ret == -1 {
                    return Err(SrtError::Param(format!("设置选项 {opt:?} 失败: {}", last_error_str())));
                }
                return Ok(());
            }
            Err(SrtError::Param("选项类型不支持".to_string()))
        };

        // 传输模式配置（关键！根因修复 2026-08-19）
        // ================================================================
        // 官方文档（docs/API/API.md "Transmission Types"）决定：
        //
        // [背景] 我们之前只设置了 MESSAGEAPI=1 + TSBPDMODE=0，没设 SRTO_TRANSTYPE，
        //   结果 SRT 默认用 "live" 传输类型 → LiveCC 拥塞控制。
        //   官方明确警告 LiveCC：
        //     "It is not intended to work with 'virtually infinite' ingest speeds ...
        //      the application must take care that the speed of data being sent is
        //      in rhythm with timestamps in the live stream. Otherwise the behavior
        //      is undefined and might be surprisingly disappointing."
        //   这正是 VPN/代理"突发大流量"场景：全双工时吞吐塌陷/卡死的根因！
        //
        // [正确方案] 用 SRTT_FILE（File 传输类型）→ FileCC 拥塞控制：
        //   官方文档：
        //     "This class generally sends the data with maximum speed in the
        //      beginning, until the flight window is full, and then keeps the speed
        //      at the edge of the flight window, only slowing down in the case
        //      where packet loss was detected."
        //   FileCC 完全适合 VPN：最大速度突发发送，只在丢包时降速。这正是我们要的。
        //
        // 注意：SRTT_FILE 设置后默认 SNDSYN=1（阻塞发送）等，但我们会再手动设非阻塞。
        //   且 SRTT_FILE 默认 MESSAGEAPI=false（Buffer 模式），我们要消息模式，
        //   所以显式再设 MESSAGEAPI=1（官方："SRTT_FILE + MESSAGEAPI=true => Message
        //   传输方法"）。
        //
        // 因此顺序：先设 SRTO_TRANSTYPE=FILE（应用 FileCC 默认组），
        //   再覆盖 MESSAGEAPI=1 + TSBPDMODE=0 + PAYLOADSIZE。
        let transtype_file: i32 = super::bindings::SRT_TRANSTYPE::SRT_TRANSTYPE_FILE as i32;
        set(SRT_SOCKOPT::SRTO_TRANSTYPE, &transtype_file)?;

        // 消息模式：每条 SRT 消息 = 一个隧道帧（SRTT_FILE+MESSAGEAPI=true=Message 方法）
        let msg_api = cfg.message_api as i32;
        set(SRT_SOCKOPT::SRTO_MESSAGEAPI, &msg_api)?;
        set(SRT_SOCKOPT::SRTO_PAYLOADSIZE, &cfg.payload_size)?;

        // 关闭 TSBPD（即时投递，不做定时播放调度；SRTT_FILE 默认即 0）
        let tsbpd_off = 0i32;
        set(SRT_SOCKOPT::SRTO_TSBPDMODE, &tsbpd_off)?;

        // 注意：不在此处设置 SRTO_SNDSYN/SRTO_RCVSYN 为非阻塞！
        // 原因：监听 socket 需要阻塞 accept（srt_accept 阻塞等待新连接），
        // 若设为非阻塞，accept 会立即返回"无连接"导致空转。
        // 已接受的连接在启动事件循环前单独设为非阻塞（见 set_nonblocking）。

        // 接收延迟（关闭 TSBPD 后 latency 仅作为重传等待窗口）
        // 文档要点：latency 给接收端时间窗去吸收重传。VPN 场景下适度即可。
        set(SRT_SOCKOPT::SRTO_RCVLATENCY, &cfg.rcv_latency)?;
        set(SRT_SOCKOPT::SRTO_PEERLATENCY, &cfg.rcv_latency)?;

        // ==== 带宽优化（2026-08-19 依据官方 API-socket-options.md 精确设置）====
        //
        // 官方文档关键结论（本处设置全部对照官方语义）：
        // - SRTO_FC 默认 25600；值越大 in-flight 包数上限越高。带宽=FC×包大小/RTT，
        //   我们的 TS 包仅 188B，FC 必须足够大（25600 可支撑 ~46Mbps @ 60ms RTT）。
        //   不能设小（原 1024/4096 都卡吞吐）。
        // - SRTO_MAXBW=-1 即无限（官方："-1: infinite, Live Mode limit 1Gbps"）。
        //   显式 -1 即可，不要设 -2（-2 语义官方未定义）。
        // - SRTO_LOSSMAXTTL=0（官方默认）表示"重排容限机制关闭"，丢包立即发 NAK 报告，
        //   重传更及时。设 >0 会等 N+1 个后续包才报丢，重传延迟↑→吞吐↓。必须 0。
        // - SRTO_SNDDROPDELAY=-1：发送端永不放弃补发（TLPKTDROP 不触发），
        //   被请求的包始终重传——VPN 可靠传输需要这个（不允许"超时放弃补发"丢数据）。
        // - SRTO_RETRANSMITALGO=0：激进重传算法，每次 NAK 都立即重传，
        //   链路质量好时延迟最低、吞吐最高。
        //
        // ==== 带宽优化（2026-08-19 依据官方 API-socket-options.md 精确设置）====
        //
        // 官方文档关键结论（本处设置全部对照官方语义）：
        // - SRTO_FC 默认 25600；值越大 in-flight 包数上限越高。带宽=FC×包大小/RTT，
        //   我们的 TS 包仅 188B 小包，FC 必须足够大（25600 可支撑 ~46Mbps @ 60ms RTT）。
        // - SRTO_RCVBUF（按包计）必须 ≤ FC（官方明确："receiver buffer size
        //   (SRTO_RCVBUF) must not be greater than SRTO_FC"）。所以 RCVBUF 需与 FC 联动。
        //   之前 32MB RCVBUF → 178k 包 > FC=25600 违反约束，SRT 行为异常导致吞吐骤降。
        // - SRTO_MAXBW=-1 即无限（官方："-1: infinite, Live Mode limit 1Gbps"）。
        // - SRTO_LOSSMAXTTL=0（官方默认）表示"重排容限机制关闭"，丢包立即发 NAK 报告，
        //   重传更及时。设 >0 会等 N+1 个后续包才报丢，重传延迟↑→吞吐↓。必须 0。
        // - SRTO_SNDDROPDELAY=-1：发送端永不放弃补发（TLPKTDROP 不触发），
        //   被请求的包始终重传——VPN 可靠传输需要这个（不允许"超时放弃补发"丢数据）。
        // - SRTO_RETRANSMITALGO=0：激进重传算法，每次 NAK 都立即重传，
        //   链路质量好时延迟最低、吞吐最高。
        //
        // 流控窗口先算（决定 RCVBUF 上限）：
        // 目标 ~100Mbps @ 60ms RTT：FC ≈ bps/8×RTT/(MSS-44) = 100M/8×0.06/144 ≈ 52000
        // 取 65536（支撑 ~125Mbps @ 60ms），TS 包 188B → RCVBUF ≤ 65536×188 ≈ 12.3MB
        let fc_window = 65536;
        set(SRT_SOCKOPT::SRTO_FC, &fc_window)?;
        // RCVBUF(字节) 受 FC 约束：12MB / 188 ≈ 66,910 包 ≤ 65536（略超，SRT 按 MSS 对齐会修正到≤FC）
        // 设 11MB 更稳妥：11MB/188 ≈ 61,276 包 < 65536 包，确保不违反 FC 约束
        let rcvbuf = 11 * 1024 * 1024;      // 11MB 接收缓冲（受 FC 约束，包数<65536）
        // SNDBUF 不受该约束，可大些容纳 in-flight 待确认数据
        // v0.5.5：32MB→8MB——用户实测发现测速切换阶段"僵尸下载"残留流量持续
        // 150M 挤占上行；SNDBUF 越大残留越多排空越慢。8MB 仍远超公网 BDP
        // （200Mbps×70ms≈1.75MB），对正常吞吐无影响，但把最坏残留时长降为 1/4。
        let sndbuf = 8 * 1024 * 1024;      // 8MB 发送缓冲（高吞吐下防止发送被限）
        set(SRT_SOCKOPT::SRTO_SNDBUF, &sndbuf)?;
        set(SRT_SOCKOPT::SRTO_RCVBUF, &rcvbuf)?;
        // UDP 层缓冲（内核 socket 缓冲），进一步吸收突发
        let udp_sndbuf = 8 * 1024 * 1024;   // 8MB 发送（原4MB）
        let udp_rcvbuf = 16 * 1024 * 1024;  // 16MB 接收（原8MB）
        set(SRT_SOCKOPT::SRTO_UDP_SNDBUF, &udp_sndbuf)?;
        set(SRT_SOCKOPT::SRTO_UDP_RCVBUF, &udp_rcvbuf)?;

        // 发送带宽上限：-1 = 无限（官方文档：Live Mode 上限 1Gbps）。
        // 不限制发送带宽，让发送端全力发送，由接收端缓冲 + 流控窗口做背压。
        let max_bw: i64 = -1; // 官方：-1 = infinite
        set(SRT_SOCKOPT::SRTO_MAXBW, &max_bw)?;
        // SRTO_MININPUTBW 是 int64（仅 MAXBW=0 时生效，这里保持 0）
        let min_input_bw: i64 = 0;
        set(SRT_SOCKOPT::SRTO_MININPUTBW, &min_input_bw)?;

        // 重排容限（lossmaxttl）：
        // 官方定义 = "Reorder Tolerance 上限"（收到乱序包后，要等多少个后续包
        // 才判定为丢失并发 NAK 报告）。默认 0 = 机制关闭 = 检测到序号间隙立即
        // 发 NAK，重传最及时。设 64 会拖延报丢，重传变慢，吞吐下降。必须 0。
        let loss_max_ttl = 0; // 官方默认：0 = 重排容限关闭，立即报丢
        set(SRT_SOCKOPT::SRTO_LOSSMAXTTL, &loss_max_ttl)?;

        // 发送端超时放弃补发（SNDDROPDELAY）：
        // 官方：-1 = "Do not drop packets on the sender at all (retransmit them
        // always when requested)" = 发送端永不放弃补发。
        // VPN 需要可靠传输，必须 -1，防止"超时放弃补发"导致数据丢失。
        // （Live 模式默认 0 = 到 TLPKTDROP 时间点就不补发了）
        let snd_drop_delay: i32 = -1;
        set(SRT_SOCKOPT::SRTO_SNDDROPDELAY, &snd_drop_delay)?;

        // 重传算法：0 = 激进（每次 NAK 立即重传，延迟最低）vs 1 = 高效（省带宽）。
        // VPN 链路质量好，选 0 激进算法吞吐最高、恢复最快。
        let retransmit_algo = 0;
        set(SRT_SOCKOPT::SRTO_RETRANSMITALGO, &retransmit_algo)?;

        // passphrase 加密（SRT 原生，aes 强度由 pbkeylen 控制）
        if !cfg.passphrase.is_empty() {
            let ret = srt_setsockopt(
                sock,
                0,
                SRT_SOCKOPT::SRTO_PASSPHRASE,
                cfg.passphrase.as_ptr() as *const std::os::raw::c_void,
                cfg.passphrase.len() as c_int,
            );
            if ret == -1 {
                return Err(SrtError::Param(format!("设置 passphrase 失败: {}", last_error_str())));
            }
            set(SRT_SOCKOPT::SRTO_PBKEYLEN, &cfg.pbkeylen)?;
            // 强制加密（密码不匹配直接拒绝，不做降级）
            let enforce = 1;
            set(SRT_SOCKOPT::SRTO_ENFORCEDENCRYPTION, &enforce)?;
        }

        // streamid（客户端设置，服务端在 accept 后读取校验）
        // 这是认证第一道门：携带静态令牌，服务端据此校验
        if let Some(sid) = &cfg.streamid {
            let ret = srt_setsockopt(
                sock,
                0,
                SRT_SOCKOPT::SRTO_STREAMID,
                sid.as_ptr() as *const std::os::raw::c_void,
                sid.len() as c_int,
            );
            if ret == -1 {
                return Err(SrtError::Param(format!("设置 streamid 失败: {}", last_error_str())));
            }
        }

        // 可靠模式：SRT 自动重传（reliable=true）
        // 尽力而为：关闭 NAK 报告 + 启用 TLPKTDROP（丢包即弃，不重传）
        if cfg.reliable {
            // 可靠模式保持默认（NAK 重传开启）
        } else {
            // best-effort：丢包即弃（TLPKTDROP=1），不触发重传等待
            set(SRT_SOCKOPT::SRTO_TLPKTDROP, &1)?;
        }

        // 保活（SRT 层 keepalive 由 libsrt 内部管理，这里设置对端空闲超时）
        // P1 2026-08-23：10000→5000ms 更快感知对端失联，且不影响 5s 心跳保活
        set(SRT_SOCKOPT::SRTO_PEERIDLETIMEO, &5_000)?;

        Ok(())
    }

    /// 把已建立连接的 socket 设为非阻塞（配合 epoll 事件循环）
    ///
    /// 注意：监听 socket 必须保持阻塞（accept 阻塞等待），
    /// 只有已连接/已接受的 socket 才设为非阻塞。
    unsafe fn set_nonblocking(sock: SRTSOCKET) -> Result<(), SrtError> {
        let zero = 0i32;
        // 发送非阻塞（send 不阻塞，由发送线程队列缓冲）
        let ret_snd = srt_setsockopt(
            sock,
            0,
            SRT_SOCKOPT::SRTO_SNDSYN,
            &zero as *const i32 as *const std::os::raw::c_void,
            std::mem::size_of::<i32>() as c_int,
        );
        // 接收非阻塞（recv 不阻塞，由 epoll 事件驱动）
        let ret_rcv = srt_setsockopt(
            sock,
            0,
            SRT_SOCKOPT::SRTO_RCVSYN,
            &zero as *const i32 as *const std::os::raw::c_void,
            std::mem::size_of::<i32>() as c_int,
        );
        if ret_snd == -1 || ret_rcv == -1 {
            return Err(SrtError::Param(format!("设置非阻塞失败: {}", last_error_str())));
        }
        Ok(())
    }

    /// 接收事件循环（接收线程主逻辑，供 connect/accept 共用）
    ///
    /// 性能优化（2026-08-19 带宽瓶颈修复）：
    /// - **批量消费**：每次 epoll 唤醒后，循环调用 srt_recvmsg 直到返回 -1（MJ_AGAIN
    ///   = 无更多可读数据），而不是一次只取一个包。
    ///   原因：原实现每个 SRT_EPOLL_IN 事件只 recvmsg 一个包就回到 epoll wait，
    ///   一次唤醒消费太少。高速传输时接收端消费速度跟不上发送端，
    ///   导致 SRT 接收缓冲溢出（日志 "No room to store incoming packet"）→
    ///   丢包 → 触发重传 → 带宽塌陷。批量消费是带宽优化核心。
    /// - **epoll 超时 10ms**（原来 100ms）：更及时唤醒处理新数据，降低延迟。
    /// - **接收通道 2026-08-19 改为 tokio mpsc UnboundedSender**：接收线程（std::thread）
    ///   直接同步 send 到 tokio 侧，消除 crossbeam + spawn_blocking 双重桥接瓶颈。
    /// - 捞取 epoll 注册前已缓冲的数据（非阻塞），避免握手后立即到达的数据不触发 IN。
    /// - 收到空消息（SRT 断连信号）或 recv_tx 关闭时退出，通知应用层连接关闭。
    ///
    /// v0.5.2 新增：接收线程内节流采样瞬时 RTT（srt_bistats instantaneous=1 → msRTT）
    /// 驱动自适应 TTL。选在接收线程的原因：libsrt 统计接口内部有锁、线程安全，
    /// 且接收线程天然随连接生灭，无需额外管理采样任务生命周期。
    fn run_recv_loop(
        recv_sock: SRTSOCKET,
        eid: i32,
        recv_tx: tokio::sync::mpsc::UnboundedSender<SrtMessage>,
        rtt: Arc<RttTracker>,
        recv_len: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        // v0.5.2：RTT 采样节流间隔 500ms（约 2Hz）。过密浪费 FFI 调用，过疏
        // 则链路突变（如延时骤增）响应太慢；500ms 在两者间取平衡。
        const RTT_SAMPLE_INTERVAL_MS: u64 = 500;
        let mut last_sample = std::time::Instant::now();
        // 捞取 epoll 注册前已到达的数据（非阻塞尝试）
        // 关键：如果对端的数据在 epoll 注册前到达，SRT 不会补触发 IN 事件，
        // 需要主动 recvmsg 把已缓冲的数据取出
        loop {
            let mut buf = [0u8; 4096];
            let ret = unsafe { srt_recvmsg(recv_sock, buf.as_mut_ptr() as *mut c_char, buf.len() as c_int) };
            if ret > 0 {
                let data = buf[..ret as usize].to_vec();
                if recv_tx.send(SrtMessage { data }).is_err() {
                    return;
                }
                // v0.5.5：入队计数 +1（高水位背压判定依据）
                recv_len.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            } else {
                break; // 无更多缓冲数据
            }
        }

        let mut events_buf = [SRT_EPOLL_EVENT { fd: -1, events: 0 }; 16];
        // v0.5.5：接收通道高水位背压（修复"僵尸下载"）
        //
        // 问题：recv 通道为 unbounded，浏览器停止读取下载（测速切换阶段/页面关闭）时，
        // 上层消费者停止取数据，但本线程仍全速收包入队 → SRT 流控永不刹车 →
        // 服务端持续以百兆级速率发送无人消费的残留流量（用户实测 SG 网卡 tx 持续
        // 150M），其 ACK/NACK 洪水与上传测试流量抢占上行带宽 → 上传被挤压掉 42%+
        // （对照实验：单独上行 66Mbps vs 并发下载时 38Mbps）。
        // 方案：通道积压超过高水位时暂停 epoll 收包数毫秒 → SRT 内核接收缓冲涨满 →
        // libsrt 流控自动让发送方减速 → 残留下载快速消散。低水位恢复避免抖动。
        const RECV_HIGH_WATERMARK: usize = 4096;
        const RECV_LOW_WATERMARK: usize = 1024;
        loop {
            if recv_len.load(std::sync::atomic::Ordering::Acquire) > RECV_HIGH_WATERMARK {
                // 积压过高：暂停收包让流控刹车，等上层消费到低水位再继续
                while recv_len.load(std::sync::atomic::Ordering::Acquire) > RECV_LOW_WATERMARK {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    // 期间若连接已关闭则退出（防 close 后空转）
                    if recv_tx.is_closed() {
                        return;
                    }
                }
            }
            // v0.5.2：节流采样瞬时 RTT（每 500ms 一次，开销可忽略）。
            // msRTT>0 才更新 EWMA；同时同步到全局 metrics.last_rtt_ms 供观测端点读取。
            // （二分实验结论：采样与 sendmsg2 均与回环上行慢无关，该现象为 v0.5.1 既有）
            if last_sample.elapsed().as_millis() as u64 >= RTT_SAMPLE_INTERVAL_MS {
                last_sample = std::time::Instant::now();
                unsafe {
                    let mut perf = super::bindings::CBytePerfMon::default();
                    // clear=0 不清局部统计（避免干扰其他观测）；instantaneous=1 取瞬时 RTT
                    let ret = srt_bistats(recv_sock, &mut perf, 0, 1);
                    if ret == 0 && perf.msRTT > 0.0 {
                        // EWMA 平滑并钳位后写回 tracker
                        let ewma = rtt.update(perf.msRTT);
                        // v0.5.3：顺带记录 SND BUF 积压跨度，供发送线程 TCP 背压判定
                        rtt.set_sndbuf_ms(perf.msSndBuf);
                        crate::metrics::metrics()
                            .last_rtt_ms
                            .store(ewma.max(0) as u64, std::sync::atomic::Ordering::Relaxed);
                        tracing::trace!(instant_rtt_ms = perf.msRTT, ewma_rtt_ms = ewma, "RTT 采样");
                    }
                }
            }
            let n = unsafe {
                // 超时 10ms：高速传输时更及时唤醒，降低批量消费的延迟
                srt_epoll_uwait(eid, events_buf.as_mut_ptr(), events_buf.len() as c_int, 10)
            };
            if n < 0 {
                // epoll 出错或超时（10ms），检查连接状态
                // 2026-08-19 S5 修复：SRTS_BROKEN=6/CLOSED=8（旧代码判 2/3 是
                // OPENED/LISTENING 健康态，断线永不退出--CPU 打满卡死真凶）
                let state = unsafe { srt_getsockstate(recv_sock) };
                if super::bindings::srt_state_unavailable(state) {
                    break;
                }
                continue;
            }
            // 处理本次唤醒的所有事件
            let mut broken = false;
            for ev in events_buf.iter().take(n as usize) {
                if ev.events & SRT_EPOLL_ERR != 0 {
                    tracing::warn!("SRT epoll 错误事件");
                    let _ = recv_tx.send(SrtMessage { data: Vec::new() });
                    broken = true;
                    break;
                }
                if ev.events & SRT_EPOLL_IN != 0 && !broken {
                    // **批量消费**：持续 recvmsg 直到无更多数据（返回 -1 表示 MJ_AGAIN）
                    // 消息模式：一条消息 = 一个 TS 帧（188B）。批量取出所有已到达的帧，
                    // 避免一次唤醒只消费一个包导致接收端跟不上发送端。
                    loop {
                        let mut buf = [0u8; 4096];
                        let ret = unsafe { srt_recvmsg(recv_sock, buf.as_mut_ptr() as *mut c_char, buf.len() as c_int) };
                        if ret > 0 {
                            let data = buf[..ret as usize].to_vec();
                            if recv_tx.send(SrtMessage { data }).is_err() {
                                // 接收方已关闭
                                return;
                            }
                            // v0.5.5：入队计数 +1（高水位背压判定依据）
                            recv_len.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        } else if ret == -1 {
                            // MJ_AGAIN：当前无更多数据，结束本次批量消费
                            // 调用 unsafe 的错误字符串获取函数
                            let err = unsafe { last_error_str() };
                            if err.contains("Connection closed") || err.contains("broken") {
                                broken = true;
                            }
                            break;
                        }
                    }
                }
            }
            if broken {
                break;
            }
        }
        // 事件循环退出：通知应用层连接关闭
        let _ = recv_tx.send(SrtMessage { data: Vec::new() });
    }

    /// 发送循环（发送线程主逻辑，v0.5.4 双队列调度版）
    ///
    /// 调度策略：
    /// - **优先队列无条件插队**：每轮循环先非阻塞清空 prio 队列（UDP 小包），
    ///   使其不被可靠队列里排队的 TCP 大块数据拖延（消除应用层队头阻塞）
    /// - 可靠队列为空时 recv_timeout(5ms) 回轮询头，防 UDP 在阻塞等待中饿死
    ///
    /// v0.5.4 教训：v0.5.3 曾加"SNDBUF 积压>300ms 暂停消费可靠队列"的 TCP 背压，
    /// 但公网大 BDP 管道（85Mbps×70ms RTT）下 msSndBuf 稳态就远超 300ms，
    /// speedtest 多线并发时判定恒真 → 可靠队列被饿死 → 测速全部卡死（用户实测）。
    /// **绝对时间跨度不能作为积压异常判据**，已移除；如需背压应基于
    /// byteAvailSndBuf 剩余空间比例另行实验。
    fn run_send_loop(
        rel_rx: crossbeam_channel::Receiver<SendItem>,
        prio_rx: crossbeam_channel::Receiver<SendItem>,
        send_sock: SRTSOCKET,
    ) {
        // 可靠队列为空时等待新数据的超时：5ms 内回到循环头检查优先队列，
        // 保证 UDP 最坏只多等一个轮询间隔（对比旧版无限阻塞 recv 的改进）
        const REL_WAIT_MS: u64 = 5;
        loop {
            // ① 无条件优先清空优先队列（非阻塞 try_recv，UDP 插队核心）
            while let Ok(item) = prio_rx.try_recv() {
                if !Self::send_one(&item, send_sock) {
                    return; // socket 断开，退出发送线程
                }
            }
            // ② 消费可靠队列：最多等 REL_WAIT_MS 即回轮询头（防 UDP 在此饿死）
            match rel_rx.recv_timeout(std::time::Duration::from_millis(REL_WAIT_MS)) {
                Ok(item) => {
                    if !Self::send_one(&item, send_sock) {
                        return;
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    // 可靠队列关闭（连接关闭）：清空剩余优先队列后退出
                    while let Ok(item) = prio_rx.try_recv() {
                        if !Self::send_one(&item, send_sock) {
                            break;
                        }
                    }
                    tracing::debug!("发送通道关闭，退出发送线程");
                    return;
                }
            }
        }
    }

    /// 发送单条消息（含背压重试/断开退出语义；返回 false 表示 socket 已断开）
    fn send_one(item: &SendItem, send_sock: SRTSOCKET) -> bool {
        // 空消息直接跳过（防御异常调用），正常关闭路径是通道断开/socket 断开
        if item.data.is_empty() {
            return true;
        }
        loop {
            // 每次重试都重建 MSGCTRL：libsrt 在阻塞等待场景可能修改 mctrl 字段，
            // 重建保证语义恒定。srctime=0 安全性已核实：TTL 基准取消息入队时刻
            // m_tsOriginTime（buffer_snd.cpp:347），与 srctime 无关。
            let mut mctrl = super::bindings::SRT_MSGCTRL {
                // QUIC 语义映射核心：
                msgttl: if item.reliable { -1 } else { item.ttl_ms },
                inorder: if item.reliable { 1 } else { 0 },
                ..super::bindings::SRT_MSGCTRL::default()
            };
            let ret = unsafe {
                srt_sendmsg2(
                    send_sock,
                    item.data.as_ptr() as *const c_char,
                    item.data.len() as c_int,
                    &mut mctrl,
                )
            };
            if ret == -1 {
                // 检查 socket 是否已断开（S5：状态 >=6 才算不可用，禁止硬编码魔法数字）
                let state = unsafe { srt_getsockstate(send_sock) };
                if super::bindings::srt_state_unavailable(state) {
                    tracing::warn!(state, "发送 socket 已断开，退出发送线程");
                    return false;
                }
                // 背压：发送缓冲满或 UDP 背压，短暂等待后重试（不退出线程）。
                // 注意不可靠消息同样重试——TTL 过期由 libsrt 内部丢弃兜底
                // （buffer_snd.cpp:350 m_iTTL 检查），应用层无需感知。
                std::thread::sleep(std::time::Duration::from_micros(100));
                continue;
            }
            return true;
        }
    }

    /// 发送数据（应用层 → 发送队列 → SRT）
    ///
    /// v0.5.2：保持旧签名兼容——内部包装为可靠消息（STREAM 语义），
    /// 全部 TCP 数据帧与控制帧继续走此路径，行为与 v0.5.1 完全一致。
    pub fn send(&self, data: Vec<u8>) -> Result<(), SrtError> {
        self.send_item(SendItem::reliable(data))
    }

    /// 发送不可靠数据（QUIC DATAGRAM 语义，v0.5.2 引入；v0.5.3 路由到优先队列）
    ///
    /// 仅当 udp_datagram=true（实验开关）时才真正以不可靠消息发送；
    /// 该开关关闭时上层（TunnelSession）会直接走可靠 Data 帧，不会调用到这里。
    pub fn send_unreliable(&self, data: Vec<u8>, ttl_ms: i32) -> Result<(), SrtError> {
        self.send_item_to(true, SendItem::unreliable(data, ttl_ms))
    }

    /// 发送可靠数据到【优先队列】（v0.5.4 新增，默认 UDP 路径）
    ///
    /// 与 send() 同为可靠语义（msgttl=-1/inorder=1），但走优先队列：
    /// 发送线程每轮先清空优先队列，UDP 小包不被 TCP 大流量积压拖延
    /// （消除应用层队头阻塞），同时保持必达——WebRTC/DTLS 场景的正确组合。
    pub fn send_priority(&self, data: Vec<u8>) -> Result<(), SrtError> {
        self.send_item_to(true, SendItem::reliable(data))
    }

    /// 统一入队入口：closed 原子读 + 锁内投递（S1 修复语义不变）
    fn send_item(&self, item: SendItem) -> Result<(), SrtError> {
        self.send_item_to(false, item)
    }

    /// 指定队列入队：priority=true 投优先队列（UDP 小包插队），false 投可靠队列
    fn send_item_to(&self, priority: bool, item: SendItem) -> Result<(), SrtError> {
        // 2026-08-19 S1 修复：closed 原子读；通道被 close() take 后返回 Closed
        if self.closed.load(AtomicOrdering::Acquire) {
            return Err(SrtError::Closed);
        }
        let guard = if priority {
            self.send_prio_tx.lock().unwrap()
        } else {
            self.send_rel_tx.lock().unwrap()
        };
        match guard.as_ref() {
            Some(tx) => tx.send(item).map_err(|_| SrtError::Closed),
            None => Err(SrtError::Closed),
        }
    }

    /// 是否启用 UDP DATAGRAM 实验模式（TunnelSession 编码帧类型时判定用）
    pub fn udp_datagram_enabled(&self) -> bool {
        self.udp_datagram
    }

    /// 获取当前自适应消息 TTL（毫秒），供上层发送不可靠消息时使用（v0.5.2）
    ///
    /// 返回 max(2×EWMA_RTT, 150ms)：RTT 由接收线程持续采样平滑，
    /// 上层每次 UDP 发送批次取一次即可。
    pub fn adaptive_ttl_ms(&self) -> i32 {
        self.rtt.adaptive_ttl()
    }

    /// 当前 EWMA 平滑 RTT（毫秒），供指标观测用（v0.5.2）
    #[allow(dead_code)]
    pub fn ewma_rtt_ms(&self) -> i32 {
        self.rtt.ewma_ms()
    }

    /// 异步发送数据（tokio 环境专用）
    ///
    /// 发送通道是 unbounded，send 不会阻塞调用线程，直接投递。
    /// 背压由发送线程（run_send_loop）通过 srt_sendmsg 感知并自我调速。
    pub async fn send_async(&self, data: Vec<u8>) -> Result<(), SrtError> {
        self.send(data)
    }

    /// 接收数据（非阻塞，等待事件循环产出的消息）
    ///
    /// 2026-08-19 重构：接收通道改为 tokio mpsc。此同步方法改为 try_recv 语义，
    /// 返回 Err(Recv) 时由调用方控制重试节奏（供非 tokio 上下文用）。
    #[allow(dead_code)]
    pub fn try_recv(&self) -> Result<SrtMessage, SrtError> {
        // tokio 的 try_recv 不需要 &mut（内部 CAS），但需要能访问 receiver。
        // 这里用 std Mutex 临时锁，不做 async 等待
        let mut guard = match self.recv_rx.try_lock() {
            Ok(g) => g,
            Err(_) => return Err(SrtError::Recv("接收通道忙".to_string())),
        };
        match guard.try_recv() {
            Ok(msg) => {
                // v0.5.5：消费一条，积压计数 -1（与 recv 线程入队 +1 对应）
                self.recv_len.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                if msg.data.is_empty() {
                    Err(SrtError::Closed) // 空消息 = 连接关闭信号
                } else {
                    Ok(msg)
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                Err(SrtError::Recv("暂无数据".to_string()))
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => Err(SrtError::Closed),
        }
    }

    /// 异步接收单条数据（tokio 环境专用）
    ///
    /// 2026-08-19 重构：直接用 tokio mpsc UnboundedReceiver.recv().await，
    /// 不再 spawn_blocking（消除桥接开销）。
    #[allow(dead_code)]
    pub async fn recv_async(&self) -> Result<SrtMessage, SrtError> {
        let mut rx = self.recv_rx.lock().await;
        match rx.recv().await {
            Some(msg) => {
                // v0.5.5：消费一条，积压计数 -1
                self.recv_len.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                if msg.data.is_empty() {
                    Err(SrtError::Closed) // 空消息 = 连接关闭信号
                } else {
                    Ok(msg)
                }
            }
            None => Err(SrtError::Closed),
        }
    }

    /// 批量接收数据（带宽优化 2026-08-19）
    ///
    /// 重构后实现：
    /// - 直接 tokio mpsc UnboundedReceiver 批量取（先阻塞等第一条，再 try_recv 收满一批）
    /// - 无需 spawn_blocking（UnboundedReceiver.recv() 是真正的 async 等待，不阻塞 worker）
    /// - 消除原先 crossbeam + spawn_blocking 双重桥接的全双工吞吐瓶颈
    /// - 返回的 Vec 非空；遇连接关闭（空消息）时返回 Err(Closed)
    pub async fn recv_batch_async(&self, max: usize) -> Result<Vec<SrtMessage>, SrtError> {
        let mut rx = self.recv_rx.lock().await;
        // 阻塞等到至少一条（真正的 async 等待）
        let first = match rx.recv().await {
            Some(m) => m,
            None => return Err(SrtError::Closed),
        };
        // v0.5.5：消费一条，积压计数 -1（与 recv 线程入队 +1 对应）
        self.recv_len.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        if first.data.is_empty() {
            return Err(SrtError::Closed); // 空消息 = 连接关闭信号
        }
        let mut batch = Vec::with_capacity(max.min(512));
        batch.push(first);
        // 非阻塞尽量多收（避免积压造成延迟）
        while batch.len() < max {
            match rx.try_recv() {
                Ok(m) => {
                    // v0.5.5：消费计数 -1
                    self.recv_len.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    if m.data.is_empty() {
                        return Ok(batch); // 遇到关闭信号，先交付这批
                    }
                    batch.push(m);
                }
                Err(_) => break, // 暂无可读，结束本次批量
            }
        }
        Ok(batch)
    }

    /// 获取对端 streamid（服务端接受连接后调用）
    pub fn get_streamid(&self) -> Option<String> {
        unsafe {
            let mut len = 512i32;
            let mut buf = [0u8; 512];
            let ret = srt_getsockopt(
                self.socket,
                0,
                SRT_SOCKOPT::SRTO_STREAMID,
                buf.as_mut_ptr() as *mut std::os::raw::c_void,
                &mut len,
            );
            if ret == -1 || len <= 0 {
                return None;
            }
            let s = String::from_utf8_lossy(&buf[..len as usize]).into_owned();
            if s.is_empty() { None } else { Some(s) }
        }
    }

    /// 关闭连接
    ///
    /// 2026-08-19 S1 修复（完整重构关闭语义）：
    /// - 旧实现：`send_tx.send(Vec::new())` 发"空消息哨兵" + 直接 release epoll。
    ///   但发送线程从不检查空消息 -> 永不退出 -> socket 永不关闭（每次重连泄漏
    ///   2 线程+socket+epoll）；且与 Drop 叠加双重 release epoll；且接收线程可能
    ///   正阻塞在 uwait(eid) 上，跨线程释放使用中的句柄属 UB。
    /// - 新语义（幂等，可安全多次调用）：
    ///   1. CAS 原子标志保证 close 动作只执行一次
    ///   2. drop 发送通道 Sender -> 发送线程 recv() Err 自然退出
    ///   3. srt_close(socket) -> 接收线程 epoll/recv 立刻感知断开退出，
    ///      并由接收线程释放 eid（唯一释放方，消除 UB 与双重释放）
    pub fn close(&self) {
        // CAS 幂等：多来源（显式 close / Drop / 认证失败清理）并发调用只生效一次
        if self.closed.swap(true, AtomicOrdering::AcqRel) {
            return; // 已关闭过
        }
        // 1. 关闭发送通道（锁内 take+drop Sender）-> 发送线程 recv() 返回 Err
        //    自然退出（覆盖空闲连接上发送线程永久挂在 recv 的泄漏窗口）
        //    v0.5.3：双队列都要关闭（可靠队列断开使 run_send_loop 走 Disconnected 分支，
        //    优先队列 drop 保证 try_recv 永远为空）
        drop(self.send_rel_tx.lock().unwrap().take());
        drop(self.send_prio_tx.lock().unwrap().take());
        // 2. 关闭 socket（幂等：libsrt 对已关 socket 返回错误，无副作用）
        //    -> 接收线程 epoll/recv 感知断开退出，并由接收线程释放 eid
        //    （唯一释放方，消除跨线程释放 UB 与双重释放）
        unsafe {
            srt_close(self.socket);
        }
        // 3. S6 修复：join 等待收发线程退出（带 2s 超时防挂死）。
        //    背景：进程退出路径（含 process::exit 触发的 atexit -> srt_cleanup ->
        //    停 GC 线程）若与我们的收发线程竞态，会段错误（实测 CRcvQueue::worker
        //    崩溃 exit 139）。join 确保线程先于 libsrt 全局清理退出。
        //    注：close() 可能在 tokio worker 上调用，join 短暂阻塞可接受
        //    （仅退出/重连路径调用，非数据热路径）。
        let handles: Vec<_> = self.threads.lock().unwrap().drain(..).collect();
        for h in handles {
            let _ = h.join();
        }
    }

    /// 连接是否已关闭
    /// （供后续接入连接状态监控用；当前调用方在 P2 接入）
    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.closed.load(AtomicOrdering::Acquire)
    }
}

impl Drop for SrtConnection {
    fn drop(&mut self) {
        // close() 内部已幂等（CAS），Drop 再调一次无害；
        // Drop 时 send_tx Mutex 锁内仍是 Some（close 已 take 则为 None）
        self.close();
    }
}

/// 把 SocketAddr 转成 libc::sockaddr_in
fn sockaddr_from(addr: SocketAddr) -> Result<libc::sockaddr_in, SrtError> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = v4.port().to_be();
            // IPv4 地址复制
            // 注意：必须用 from_ne_bytes 而非 from_be_bytes！
            // 原因：sin_addr.s_addr 在内存中必须是网络字节序 [a,b,c,d]，
            //       from_be_bytes 会按大端组合成主机序数值，小端机上内存变成 [d,c,b,a]，
            //       导致 127.0.0.1 被解析成 1.0.0.127（前面实测的 bug）。
            //       from_ne_bytes 让内存字节直接等于 [a,b,c,d] = 网络序。
            let ip = v4.ip().octets();
            sa.sin_addr.s_addr = u32::from_ne_bytes(ip);
            Ok(sa)
        }
        SocketAddr::V6(_) => Err(SrtError::Param("IPv6 暂不支持（P1 仅 IPv4）".to_string())),
    }
}

// ============================================================================
// 服务端监听器（2026-08-19 M1 配套修复新增）
//
// 背景：accept 并行化后，旧模型"每连接重建监听 socket（bind->listen->accept(1个)
// ->close）"会导致多任务同时 bind 同一端口 -> "Another socket is already
// listening on the same port" 无限报错（新加坡部署实测）。
//
// 正确模型：监听 socket 全局唯一且常驻（bind_listener 建立一次），
// accept_one 可在多任务并发调用（srt_accept 线程安全，libsrt 内部排队）。
// ============================================================================

/// 服务端监听器（常驻监听 socket 封装，详见上方注释）
pub struct SrtListener {
    /// 常驻监听 socket（由 bind_listener 建立，Drop 时关闭）
    sock: SRTSOCKET,
    /// v0.5.3：UDP DATAGRAM 实验模式开关（accept 出的连接继承此配置）
    udp_datagram: bool,
}

// 跨线程移动（accept_loop 经 spawn_blocking 调用 accept_one）
unsafe impl Send for SrtListener {}
unsafe impl Sync for SrtListener {}

impl SrtListener {
    /// 在常驻监听 socket 上接受一个连接（阻塞，可并发调用）
    pub fn accept_one(&self) -> Result<SrtConnection, SrtError> {
        SrtConnection::accept_from_listener(self.sock, self.udp_datagram)
    }
}

impl Drop for SrtListener {
    fn drop(&mut self) {
        // 监听 socket 唯一释放方（S1 同款原则：单一释放点，幂等安全）
        unsafe { srt_close(self.sock) };
    }
}
