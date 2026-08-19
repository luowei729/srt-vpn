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
