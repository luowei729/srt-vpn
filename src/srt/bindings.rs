//! srt/bindings.rs — libsrt 1.5.6 FFI 绑定
//!
//! 设计决策（Q2）：官方 libsrt 静态库 + Rust FFI
//! - 本文件只声明 unsafe 外部函数（对应 srt-1.5.6/srtcore/srt.h）
//! - 所有指针操作封装在 connection.rs 的安全接口内，禁止在外层直接调 FFI
//! - 枚举值必须与 srt.h 保持一致（SRT_SOCKOPT / SRT_EPOLL_OPT / SRT_TRANSTYPE）

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
// FFI 声明是完整 API 预留（部分在 P1 未用到，后续阶段启用）
#![allow(dead_code)]

use std::os::raw::{c_char, c_int, c_void};

/// SRT socket 句柄（int32_t）
pub type SRTSOCKET = i32;
/// epoll 句柄（int32_t）
pub type SRT_EPOLL_T = i32;

/// SRT 传输类型（对应 srt.h SRT_TRANSTYPE）
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SRT_TRANSTYPE {
    SRT_TRANSTYPE_LIVE = 0,   // 直播模式（本项目的伪装目标）
    SRT_TRANSTYPE_FILE = 1,   // 文件传输
}

/// SRT socket 选项（对应 srt.h SRT_SOCKOPT，值必须一致）
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SRT_SOCKOPT {
    SRTO_MSS = 0,
    SRTO_SNDSYN = 1,
    SRTO_RCVSYN = 2,
    SRTO_ISN = 3,
    SRTO_FC = 4,
    SRTO_SNDBUF = 5,
    SRTO_RCVBUF = 6,
    SRTO_LINGER = 7,
    SRTO_UDP_SNDBUF = 8,
    SRTO_UDP_RCVBUF = 9,
    SRTO_RENDEZVOUS = 12,
    SRTO_SNDTIMEO = 13,
    SRTO_RCVTIMEO = 14,
    SRTO_REUSEADDR = 15,
    SRTO_MAXBW = 16,
    SRTO_STATE = 17,
    SRTO_EVENT = 18,
    SRTO_SNDDATA = 19,
    SRTO_RCVDATA = 20,
    SRTO_SENDER = 21,
    SRTO_TSBPDMODE = 22,
    SRTO_LATENCY = 23,
    SRTO_INPUTBW = 24,
    SRTO_OHEADBW = 25,
    SRTO_PASSPHRASE = 26,
    SRTO_PBKEYLEN = 27,
    SRTO_KMSTATE = 28,
    SRTO_IPTTL = 29,
    SRTO_IPTOS = 30,
    SRTO_TLPKTDROP = 31,
    SRTO_SNDDROPDELAY = 32,
    SRTO_NAKREPORT = 33,
    SRTO_VERSION = 34,
    SRTO_PEERVERSION = 35,
    SRTO_CONNTIMEO = 36,
    SRTO_DRIFTTRACER = 37,
    SRTO_MININPUTBW = 38,
    SRTO_SNDKMSTATE = 40,
    SRTO_RCVKMSTATE = 41,
    SRTO_LOSSMAXTTL = 42,
    SRTO_RCVLATENCY = 43,
    SRTO_PEERLATENCY = 44,
    SRTO_MINVERSION = 45,
    SRTO_STREAMID = 46,
    SRTO_CONGESTION = 47,
    SRTO_MESSAGEAPI = 48,
    SRTO_PAYLOADSIZE = 49,
    SRTO_TRANSTYPE = 50,
    SRTO_KMREFRESHRATE = 51,
    SRTO_KMPREANNOUNCE = 52,
    SRTO_ENFORCEDENCRYPTION = 53,
    SRTO_IPV6ONLY = 54,
    SRTO_PEERIDLETIMEO = 55,
    SRTO_BINDTODEVICE = 56,
    SRTO_GROUPCONNECT = 57,
    SRTO_GROUPMINSTABLETIMEO = 58,
    SRTO_GROUPTYPE = 59,
    SRTO_PACKETFILTER = 60,
    SRTO_RETRANSMITALGO = 61,
    SRTO_CRYPTOMODE = 62,
    SRTO_MAXREXMITBW = 63,
}

/// epoll 事件位（对应 srt.h SRT_EPOLL_OPT）
pub const SRT_EPOLL_IN: i32 = 0x1;
pub const SRT_EPOLL_OUT: i32 = 0x4;
pub const SRT_EPOLL_ERR: i32 = 0x8;
/// 连接建立事件（= SRT_EPOLL_OUT，连接成功后触发）
pub const SRT_EPOLL_CONNECT: i32 = SRT_EPOLL_OUT;

// ===== SRT socket 状态常量（对应 srt.h SRT_SOCKSTATUS，2026-08-19 S5 修复新增）=====
// 枚举完整定义（srt-1.5.6/srtcore/srt.h:159）：
//   SRTS_INIT=1, SRTS_OPENED=2, SRTS_LISTENING=3, SRTS_CONNECTING=4, SRTS_CONNECTED=5,
//   SRTS_BROKEN=6, SRTS_CLOSING=7, SRTS_CLOSED=8, SRTS_NONEXIST=9
// 历史教训：此前代码用 `state == 2 || state == 3` 判"断开"——实际是
// OPENED/LISTENING（健康状态），BROKEN(6)/CLOSED(8) 永远不匹配，
// 导致断线后收发线程永不退出 + 100µs 忙等（服务端 CPU 79% 卡死的真凶）。
pub const SRTS_BROKEN: c_int = 6;
pub const SRTS_CLOSING: c_int = 7;
pub const SRTS_CLOSED: c_int = 8;
pub const SRTS_NONEXIST: c_int = 9;

/// 判断 socket 状态是否表示连接不可用（BROKEN/CLOSING/CLOSED/NONEXIST，S5 修复）
/// 断线检测统一走本函数，禁止再硬编码魔法数字。
#[inline]
pub fn srt_state_unavailable(state: c_int) -> bool {
    state >= SRTS_BROKEN
}

/// 消息边界常量（对应 srtcore/packet.h PacketBoundaryBits）
/// 发送侧 libsrt 内部按消息分片自动设置 PB_FIRST/PB_LAST/PB_SOLO，
/// SRT_MSGCTRL.boundary 传入值仅作占位；本项目单帧 ≤1301B < payload 1316，
/// 天然单包单消息，恒为 PB_SOLO。
pub const PB_LAST: c_int = 1; // 消息最后一包
pub const PB_FIRST: c_int = 2; // 消息第一包
pub const PB_SOLO: c_int = 3; // 独立单包消息（PB_FIRST|PB_LAST）

/// SRT 消息控制结构（对应 srt.h SRT_MSGCTRL）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SRT_MSGCTRL {
    pub flags: c_int,
    pub msgttl: c_int,
    pub inorder: c_int,
    pub boundary: c_int,
    pub srctime: i64,
    pub pktseq: i32,
    pub msgno: i32,
    pub grpdata: *mut c_void,
    pub grpdata_size: usize,
}

impl Default for SRT_MSGCTRL {
    /// 默认值：与 libsrt 官方示例一致（srt_sendmsg2 调用前必须初始化全字段）
    fn default() -> Self {
        Self {
            flags: 0,
            msgttl: -1, // 默认无限 TTL（可靠语义）
            inorder: 1, // 默认保序投递
            boundary: PB_SOLO,
            srctime: 0, // TSBPD 关闭时 libsrt 会强制清零，无需应用侧填时间戳
            pktseq: 0,
            // msgno 必须 -1（=由 libsrt 自动分配）；0 会被 CUDT::sendmsg2 判为
            // "强制指定消息号"且越界（合法域 [1,MSGNO_SEQ_MAX]），抛 MN_INVAL。
            // 实测教训：msgno=0 导致发送失败并被当背压无限重试刷屏（core.cpp:6889）。
            msgno: -1,
            grpdata: std::ptr::null_mut(),
            grpdata_size: 0,
        }
    }
}

// ===== 字节级性能统计（2026-08-23 v0.5.2 新增）=====
//
// 对应 srt.h CBytePerfMon（srt.h:304-410，含 1.5.0 新增尾部字段），
// 用于 srt_bistats(instantaneous=1) 读取瞬时 RTT，驱动 per-message TTL 自适应。
//
// 布局安全关键：
// - 字段顺序/类型必须与 srt.h 逐项一致（repr(C) 自然对齐规则与 MSVC/GCC 一致）
// - srt.h 明确要求"新字段只许加在末尾"，故本定义以 1.5.6 全字段为准；
//   若未来升级 libsrt 且在中间插字段，此处必须同步重抄
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CBytePerfMon {
    // ---- global measurements（累计值）----
    pub msTimeStamp: i64,           // socket 存活时长（毫秒）
    pub pktSentTotal: i64,          // 已发数据包总数（含重传）
    pub pktRecvTotal: i64,          // 已收数据包总数
    pub pktSndLossTotal: c_int,     // 发送侧累计丢包数
    pub pktRcvLossTotal: c_int,     // 接收侧累计丢包数
    pub pktRetransTotal: c_int,     // 累计重传包数
    pub pktSentACKTotal: c_int,     // 已发 ACK 总数
    pub pktRecvACKTotal: c_int,     // 已收 ACK 总数
    pub pktSentNAKTotal: c_int,     // 已发 NAK 总数
    pub pktRecvNAKTotal: c_int,     // 已收 NAK 总数
    pub usSndDurationTotal: i64,    // 累计发送忙碌时长（微秒）
    pub pktSndDropTotal: c_int,     // 发送侧因过期丢弃的包总数
    pub pktRcvDropTotal: c_int,     // 接收侧因迟到丢弃的包总数
    pub pktRcvUndecryptTotal: c_int,// 无法解密的包总数
    pub byteSentTotal: u64,         // 已发字节总数（含重传）
    pub byteRecvTotal: u64,         // 已收字节总数
    pub byteRcvLossTotal: u64,      // 接收侧丢失字节总数
    pub byteRetransTotal: u64,      // 重传字节总数
    pub byteSndDropTotal: u64,      // 发送侧丢弃字节总数
    pub byteRcvDropTotal: u64,      // 接收侧丢弃字节总数（按平均包长估算）
    pub byteRcvUndecryptTotal: u64, // 无法解密字节总数

    // ---- local measurements（自上次查询以来的局部值）----
    pub pktSent: i64,
    pub pktRecv: i64,
    pub pktSndLoss: c_int,
    pub pktRcvLoss: c_int,
    pub pktRetrans: c_int,
    pub pktRcvRetrans: c_int,
    pub pktSentACK: c_int,
    pub pktRecvACK: c_int,
    pub pktSentNAK: c_int,
    pub pktRecvNAK: c_int,
    pub mbpsSendRate: f64,          // 发送速率 Mb/s
    pub mbpsRecvRate: f64,          // 接收速率 Mb/s
    pub usSndDuration: i64,
    pub pktReorderDistance: c_int,  // 收到乱序的距离
    pub pktRcvAvgBelatedTime: f64,  // 迟到包平均延迟
    pub pktRcvBelated: i64,         // 因迟到被忽略的包数
    pub pktSndDrop: c_int,
    pub pktRcvDrop: c_int,
    pub pktRcvUndecrypt: c_int,
    pub byteSent: u64,
    pub byteRecv: u64,
    pub byteRcvLoss: u64,
    pub byteRetrans: u64,
    pub byteSndDrop: u64,
    pub byteRcvDrop: u64,
    pub byteRcvUndecrypt: u64,

    // ---- instant measurements（瞬时值，自适应 TTL 的数据源）----
    pub usPktSndPeriod: f64,        // 包发送间隔（微秒）
    pub pktFlowWindow: c_int,       // 流控窗口（包数）
    pub pktCongestionWindow: c_int, // 拥塞窗口（包数）
    pub pktFlightSize: c_int,       // 在途包数
    pub msRTT: f64,                 // ★ RTT（毫秒）：instantaneous=1 时为瞬时值，驱动自适应 TTL
    pub mbpsBandwidth: f64,         // 估算带宽 Mb/s
    pub byteAvailSndBuf: c_int,     // 发送缓冲可用字节
    pub byteAvailRcvBuf: c_int,     // 接收缓冲可用字节

    pub mbpsMaxBW: f64,             // 带宽上限设置值 Mbps
    pub byteMSS: c_int,             // MTU
    pub pktSndBuf: c_int,           // 发送缓冲未 ACK 包数
    pub byteSndBuf: c_int,          // 发送缓冲未 ACK 字节
    pub msSndBuf: c_int,            // 发送缓冲未 ACK 时间跨度（毫秒）
    pub msSndTsbPdDelay: c_int,     // 发送侧 TSBPD 延迟
    pub pktRcvBuf: c_int,           // 接收缓冲未投递包数
    pub byteRcvBuf: c_int,          // 接收缓冲未投递字节
    pub msRcvBuf: c_int,            // 接收缓冲未投递时间跨度（毫秒）
    pub msRcvTsbPdDelay: c_int,     // 接收侧 TSBPD 延迟

    pub pktSndFilterExtraTotal: c_int, // 包过滤器额外产生的控制包总数
    pub pktRcvFilterExtraTotal: c_int, // 过滤器收到但未回供的控制包总数
    pub pktRcvFilterSupplyTotal: c_int,// FEC 重建等额外供给包总数
    pub pktRcvFilterLossTotal: c_int,  // 过滤器无法覆盖的丢包总数

    pub pktSndFilterExtra: c_int,
    pub pktRcvFilterExtra: c_int,
    pub pktRcvFilterSupply: c_int,
    pub pktRcvFilterLoss: c_int,
    pub pktReorderTolerance: c_int, // 当前乱序容限值

    // ---- New stats in 1.5.0（srt.h 要求追加在末尾的字段）----
    pub pktSentUniqueTotal: i64,    // 应用实际发送的数据包总数（不含重传）
    pub pktRecvUniqueTotal: i64,    // 应用应接收的数据包总数
    pub byteSentUniqueTotal: u64,   // 应用实际发送字节总数
    pub byteRecvUniqueTotal: u64,   // 应用应接收字节总数
    pub pktSentUnique: i64,
    pub pktRecvUnique: i64,
    pub byteSentUnique: u64,
    pub byteRecvUnique: u64,
}

/// epoll 事件结构（对应 srt.h SRT_EPOLL_EVENT）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SRT_EPOLL_EVENT {
    pub fd: SRTSOCKET,
    pub events: c_int,
}

// ===== libsrt 外部函数声明 =====

extern "C" {
    /// 初始化 libsrt 全局状态（程序启动时调用一次）
    pub fn srt_startup() -> c_int;

    /// 清理 libsrt 全局状态（程序退出时调用）
    pub fn srt_cleanup() -> c_int;

    /// 创建 SRT socket
    pub fn srt_create_socket() -> SRTSOCKET;

    /// 绑定地址
    pub fn srt_bind(u: SRTSOCKET, name: *const libc::sockaddr, namelen: c_int) -> c_int;

    /// 监听（服务端）
    pub fn srt_listen(u: SRTSOCKET, backlog: c_int) -> c_int;

    /// 接受连接（服务端）
    pub fn srt_accept(u: SRTSOCKET, addr: *mut libc::sockaddr, addrlen: *mut c_int) -> SRTSOCKET;

    /// 发起连接（客户端）
    pub fn srt_connect(u: SRTSOCKET, name: *const libc::sockaddr, namelen: c_int) -> c_int;

    /// 关闭 socket
    pub fn srt_close(u: SRTSOCKET) -> c_int;

    /// 获取对端地址
    pub fn srt_getpeername(u: SRTSOCKET, name: *mut libc::sockaddr, namelen: *mut c_int) -> c_int;

    /// 获取本地地址
    pub fn srt_getsockname(u: SRTSOCKET, name: *mut libc::sockaddr, namelen: *mut c_int) -> c_int;

    /// 设置 socket 选项（level 忽略，传 0）
    pub fn srt_setsockopt(
        u: SRTSOCKET,
        level: c_int,
        optname: SRT_SOCKOPT,
        optval: *const c_void,
        optlen: c_int,
    ) -> c_int;

    /// 获取 socket 选项
    pub fn srt_getsockopt(
        u: SRTSOCKET,
        level: c_int,
        optname: SRT_SOCKOPT,
        optval: *mut c_void,
        optlen: *mut c_int,
    ) -> c_int;

    /// 发送消息（消息模式，P1 用 srt_sendmsg 简化）
    pub fn srt_sendmsg(u: SRTSOCKET, buf: *const c_char, len: c_int, ttl: c_int, inorder: c_int) -> c_int;

    /// 接收消息（消息模式）
    pub fn srt_recvmsg(u: SRTSOCKET, buf: *mut c_char, len: c_int) -> c_int;

    /// 发送消息（带控制结构）
    pub fn srt_sendmsg2(u: SRTSOCKET, buf: *const c_char, len: c_int, mctrl: *mut SRT_MSGCTRL) -> c_int;

    /// 接收消息（带控制结构）
    pub fn srt_recvmsg2(u: SRTSOCKET, buf: *mut c_char, len: c_int, mctrl: *mut SRT_MSGCTRL) -> c_int;

    /// 字节级性能统计查询（对应 srt.h srt_bistats，v0.5.2 新增）
    /// - clear=1：同时清零局部统计；本项目传 0（只读不干扰）
    /// - instantaneous=1：msRTT 等返回瞬时值（非平滑均值），
    ///   这是自适应 TTL 选它而非 srt_bstats 的原因（链路突变能立刻感知）
    pub fn srt_bistats(u: SRTSOCKET, perf: *mut CBytePerfMon, clear: c_int, instantaneous: c_int) -> c_int;

    /// 获取最后错误码
    pub fn srt_getlasterror(errno_loc: *mut c_int) -> c_int;

    /// 获取最后错误字符串
    pub fn srt_getlasterror_str() -> *const c_char;

    /// 获取 socket 状态
    pub fn srt_getsockstate(u: SRTSOCKET) -> c_int;

    /// 创建 epoll 实例
    pub fn srt_epoll_create() -> c_int;

    /// 释放 epoll 实例
    pub fn srt_epoll_release(eid: c_int) -> c_int;

    /// 添加 socket 到 epoll
    pub fn srt_epoll_add_usock(eid: c_int, u: SRTSOCKET, events: *const c_int) -> c_int;

    /// 从 epoll 移除 socket
    pub fn srt_epoll_remove_usock(eid: c_int, u: SRTSOCKET) -> c_int;

    /// epoll 等待事件（事件结构数组版）
    pub fn srt_epoll_uwait(eid: c_int, fdsSet: *mut SRT_EPOLL_EVENT, fdsSize: c_int, msTimeOut: i64) -> c_int;

    /// 设置日志级别
    pub fn srt_setloglevel(ll: c_int);
}

// libc 依赖声明（sockaddr 等类型）
#[link(name = "c")]
extern "C" {}

/// 获取 libsrt 最后错误字符串（安全封装）
pub unsafe fn last_error_str() -> String {
    let p = srt_getlasterror_str();
    if p.is_null() {
        return "unknown error".to_string();
    }
    std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
}
