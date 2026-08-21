//! CLI 参数解析模块
//!
//! 设计原因：保持 passwall 契约——
//! - `-V` 输出 "srt-vpn <version>"（passwall com.lua 用 `awk '{print $2}'` 取版本号）
//! - `-c <配置文件>` 从 JSON 配置启动
//! - `-h` 帮助
//! 优先级：CLI > SRT_* 环境变量 > 配置文件 > 默认

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

/// SRT-VPN：SRT 外壳伪装 + quinn-proto QUIC 内核 + TUIC 协议语义 VPN
#[derive(Parser, Debug)]
#[command(
    name = "srt-vpn", // 二进制名，-V 输出 "srt-vpn <version>"
    version,           // 启用 -V/--version，输出 "srt-vpn 0.4.0"
    about = "SRT 外壳伪装 + QUIC 内核 + TUIC 协议 VPN"
)]
pub struct Cli {
    /// 配置文件路径（JSON 格式）
    ///
    /// 省略时可用 SRT_* 环境变量启动（passwall 用 -c 方式）
    #[arg(short = 'c', long = "config")]
    pub config: Option<String>,

    /// 日志级别（覆盖配置文件中的 log_level）
    ///
    /// 0=error, 1=warn, 2=info, 3=debug, 4=trace
    /// 优先级：CLI -v > 配置 log_level > 默认 info
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// 运行模式（服务端/客户端）
///
/// 从配置文件的 "mode" 字段决定，不是 CLI 参数
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// 服务端模式：监听端口，接受客户端连接，转发流量
    Server,
    /// 客户端模式：连接服务端，提供本地 SOCKS5/HTTP 代理
    Client,
}
