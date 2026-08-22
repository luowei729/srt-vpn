//! srt/mod.rs — SRT FFI 封装模块
//!
//! 设计决策（Q2）：官方 libsrt 1.5.6 静态库 + Rust FFI
//! - bindings.rs: 原始 FFI 声明（unsafe）
//! - connection.rs: 安全封装（连接管理、事件循环线程、收发接口）
//!
//! 安全边界：所有 unsafe 调用只允许出现在本模块内，
//! 上层（隧道/客户端/服务器）只能使用 connection.rs 的安全接口。

pub mod bindings;
pub mod connection;
