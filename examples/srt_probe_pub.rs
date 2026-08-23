//! 裸 SRT 公网带宽探针（v1 时代 srt_probe 复刻，隔离隧道层直接测 libsrt 吞吐）
//!
//! 用法：
//!   服务端: srt_probe srv <listen_port>
//!   客户端: srt_probe cli <remote_ip> <port> <msg_count>
//!
//! 与 v0.5.0 主程序完全一致的 SRT 配置（SRTT_FILE+MESSAGEAPI+TSBPD0+FC65536+SNDBUF32M），
//! 用于判定"公网慢"是链路/libsrt 本身，还是 srt-vpn 隧道复用层引入。

use std::os::raw::{c_char, c_int, c_void};
use std::time::Instant;

// 手写 sockaddr_in（与 C ABI 完全一致：sin_family u16 + sin_port BE u16 + sin_addr u32(NE bytes)）
// 不依赖 libc crate，让 rustc 可单文件编译（hk2 无 cargo 环境）
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}
type S = i32;
// SRT_SOCKOPT 数值（与 src/srt/bindings.rs 一致）
const T_FILE: c_int = 1; // SRT_TRANSTYPE=50 的值用 50
const OPT_TRANSTYPE: c_int = 50;
const MESSAGEAPI: c_int = 48;
const PAYLOAD: c_int = 49;
const TSBPD: c_int = 22;
const SNDBUF: c_int = 5;
const RCVBUF: c_int = 6;
const FC: c_int = 4;
const RCVSYN: c_int = 2;
const SNDSYN: c_int = 1;
const PASSPHRASE: c_int = 26;
const PBKEYLEN: c_int = 27;
const MAXBW: c_int = 16;
const LOSSMAXTTL: c_int = 42;
const SNDDROPDELAY: c_int = 32;
const RETXALGO: c_int = 61;
const RCVLATENCY: c_int = 43;
const PEERLATENCY: c_int = 44;

extern "C" {
    fn srt_startup() -> c_int;
    fn srt_cleanup() -> c_int;
    fn srt_create_socket() -> S;
    fn srt_setsockopt(u: S, l: c_int, o: c_int, v: *const c_void, n: c_int) -> c_int;
    fn srt_bind(u: S, s: *const SockaddrIn, n: c_int) -> c_int;
    fn srt_listen(u: S, b: c_int) -> c_int;
    fn srt_accept(u: S, s: *mut SockaddrIn, n: *mut c_int) -> S;
    fn srt_connect(u: S, s: *const SockaddrIn, n: c_int) -> c_int;
    fn srt_sendmsg(u: S, b: *const c_char, l: c_int, t: c_int, i: c_int) -> c_int;
    fn srt_recvmsg(u: S, b: *mut c_char, l: c_int) -> c_int;
    fn srt_close(u: S) -> c_int;
    fn srt_getlasterror_str() -> *const c_char;
    fn srt_getsockstate(u: S) -> c_int;
}

const MSG: usize = 1316;

fn le() -> String {
    unsafe {
        let p = srt_getlasterror_str();
        if p.is_null() { "?".into() } else { std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned() }
    }
}

/// 构造 sockaddr_in（注意 from_ne_bytes 是 v1 血泪教训：IPv4 字节序必须 NE）
fn sa(ip: [u8; 4], port: u16) -> SockaddrIn {
    SockaddrIn {
        sin_family: 2, // AF_INET
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes(ip), // v1 血泪教训：必须 NE 字节序
        sin_zero: [0; 8],
    }
}

/// 与主程序 apply_options 完全一致的选项集（对照实验变量控制）
/// maxbw_bps: -1=无限（主程序默认），>0 = 显式字节/秒上限（bytes/sec，libsrt 语义）
/// fc: 流窗口大小，默认 65536
fn cfgs(s: S, maxbw_bps: i64, fc: i32) {
    unsafe {
        let so = |o: c_int, v: &i32| assert_ne!(srt_setsockopt(s, 0, o, v as *const i32 as *const c_void, 4), -1, "opt{o}: {}", le());
        so(OPT_TRANSTYPE, &T_FILE); // FileCC
        so(MESSAGEAPI, &1);
        so(PAYLOAD, &(MSG as i32));
        so(TSBPD, &0);
        so(RCVLATENCY, &1000);
        so(PEERLATENCY, &1000);
        so(FC, &fc); // A/B 变量：流窗口
        so(SNDBUF, &(32 * 1024 * 1024));
        so(RCVBUF, &(11 * 1024 * 1024));
        so(SNDDROPDELAY, &-1);
        so(RETXALGO, &0);
        // MAXBW 是 i64 选项；>0 = bytes/sec 上限，FileCC 在公网高 RTT 下可能需要显式声明速率
        let maxbw: i64 = maxbw_bps;
        assert_ne!(srt_setsockopt(s, 0, MAXBW, &maxbw as *const i64 as *const c_void, 8), -1, "optMAXBW(i64): {}", le());
        so(LOSSMAXTTL, &0);
        let p = b"change-me-strong-passphrase-2026";
        assert_ne!(srt_setsockopt(s, 0, PASSPHRASE, p.as_ptr() as *const c_void, p.len() as c_int), -1, "ph");
        so(PBKEYLEN, &16);
    }
}

fn srv(port: u16, msgs: u64, maxbw_bps: i64, fc: i32) {
    unsafe {
        srt_startup();
        let s = srt_create_socket();
        cfgs(s, maxbw_bps, fc);
        let a = sa([0, 0, 0, 0], port);
        assert_ne!(srt_bind(s, &a, std::mem::size_of::<SockaddrIn>() as c_int), -1, "bind");
        assert_ne!(srt_listen(s, 128), -1, "listen");
        eprintln!("[srv] listening :{port}");
        let mut pe = std::mem::zeroed();
        let mut pl = std::mem::size_of::<SockaddrIn>() as c_int;
        let acc = srt_accept(s, &mut pe, &mut pl);
        assert!(acc != -1, "accept: {}", le());
        std::thread::sleep(std::time::Duration::from_millis(300));
        let z = 0i32;
        srt_setsockopt(acc, 0, RCVSYN, &z as *const i32 as *const c_void, 4);
        srt_setsockopt(acc, 0, SNDSYN, &z as *const i32 as *const c_void, 4);
        // 批量接收（与 run_recv_loop 相同模式），进度每 2s 打一次
        let mut b = [0u8; 4096];
        let mut n: u64 = 0;
        let mut bytes: u64 = 0;
        let st = Instant::now();
        let mut last_report = Instant::now();
        while n < msgs {
            let r = srt_recvmsg(acc, b.as_mut_ptr() as *mut c_char, b.len() as c_int);
            if r > 0 {
                n += 1;
                bytes += r as u64;
                if last_report.elapsed().as_millis() >= 2000 {
                    let el = st.elapsed().as_secs_f64();
                    eprintln!("[srv] {n} msgs {:.2}MB/s", bytes as f64 / el / 1e6);
                    last_report = Instant::now();
                }
            } else if srt_getsockstate(acc) >= 6 {
                break;
            } else {
                std::thread::sleep(std::time::Duration::from_micros(50));
            }
        }
        let el = st.elapsed().as_secs_f64();
        eprintln!("[srv DONE] {n}@{:.0}msg/s {:.2}MB/s total {:.2}MB", msgs as f64 / el, bytes as f64 / el / 1e6, bytes as f64 / 1e6);
        srt_close(acc);
        srt_close(s);
        srt_cleanup();
    }
}

fn cli(ip: [u8; 4], port: u16, msgs: u64, maxbw_bps: i64, fc: i32) {
    unsafe {
        srt_startup();
        let s = srt_create_socket();
        cfgs(s, maxbw_bps, fc);
        let a = sa(ip, port);
        assert_ne!(srt_connect(s, &a, std::mem::size_of::<SockaddrIn>() as c_int), -1, "connect: {}", le());
        std::thread::sleep(std::time::Duration::from_millis(500));
        let z = 0i32;
        srt_setsockopt(s, 0, RCVSYN, &z as *const i32 as *const c_void, 4);
        srt_setsockopt(s, 0, SNDSYN, &z as *const i32 as *const c_void, 4);
        let d = vec![0xEEu8; MSG];
        let mut n: u64 = 0;
        let mut fail: u64 = 0;
        let st = Instant::now();
        let mut last_report = Instant::now();
        while n < msgs {
            let r = srt_sendmsg(s, d.as_ptr() as *const c_char, d.len() as c_int, -1, 1);
            if r == -1 {
                fail += 1;
                if srt_getsockstate(s) >= 6 { break; }
                std::thread::sleep(std::time::Duration::from_micros(100));
            } else {
                n += 1;
                if last_report.elapsed().as_millis() >= 2000 {
                    let el = st.elapsed().as_secs_f64();
                    eprintln!("[cli] {n} sent {:.2}MB/s (MJ_AGAIN {fail})", n as f64 * MSG as f64 / el / 1e6);
                    last_report = Instant::now();
                }
            }
        }
        let el = st.elapsed().as_secs_f64();
        eprintln!("[cli DONE] {n}@{:.0}msg/s {:.2}MB/s MJ_AGAIN={fail}", n as f64 / el, n as f64 * MSG as f64 / el / 1e6);
        srt_close(s);
        srt_cleanup();
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    // 第 4/5 参数：A/B 实验变量（两端必须一致，握手会协商取交集）
    // maxbw：-1=无限（主程序默认）；如 2500000 = 2.5MB/s ≈ 20Mbps
    // fc：流窗口，默认 65536
    let maxbw: i64 = std::env::args().nth(5).unwrap_or("-1".into()).parse().unwrap();
    let fc: i32 = std::env::args().nth(6).unwrap_or("65536".into()).parse().unwrap();
    match mode.as_str() {
        "srv" => {
            let port: u16 = std::env::args().nth(2).unwrap_or("29000".into()).parse().unwrap();
            let msgs: u64 = std::env::args().nth(3).unwrap_or("200000".into()).parse().unwrap();
            srv(port, msgs, maxbw, fc);
        }
        "cli" => {
            let ipstr = std::env::args().nth(2).expect("need remote ip");
            let port: u16 = std::env::args().nth(3).unwrap_or("29000".into()).parse().unwrap();
            let msgs: u64 = std::env::args().nth(4).unwrap_or("200000".into()).parse().unwrap();
            let parts: Vec<u8> = ipstr.split('.').map(|x| x.parse().unwrap()).collect();
            cli([parts[0], parts[1], parts[2], parts[3]], port, msgs, maxbw, fc);
        }
        _ => {
            eprintln!("用法: {} srv <port> <msgs> [maxbw_bytes_per_sec] [fc] | cli <ip> <port> <msgs> [maxbw] [fc]", std::env::args().next().unwrap_or("srt_probe".into()));
        }
    }
}
