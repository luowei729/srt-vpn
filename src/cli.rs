//! cli.rs — CLI 参数解析
//!
//! 启动命令：srt-vpn -c server.conf / srt-vpn -c client.json
//! 也可不指定 -c：纯环境变量配置（Docker -e 场景，见 config::from_env）
//!
//! 参数设计（设计树 Q13）：
//! - -c: 配置文件路径（可选；省略时用环境变量构建配置，Docker -e 场景）
//! - -v: 日志级别（0-4，默认 2）
//! - -h: 帮助
//! - SOCKS5 完整设定参数（覆盖配置文件）：
//!   --socks5-listen: SOCKS5 监听地址（如 127.0.0.1:1080）
//!   --socks5-user:   SOCKS5 用户名
//!   --socks5-pass:   SOCKS5 密码
//!   --socks5-users:  多用户配置（可选，格式 user:pass 逗号分隔）
//!
//! 配置优先级：CLI > 环境变量(SRT_*) > 配置文件 > 默认值
//! -m 已移除（2026-08-20）：UDP 模式直接配置文件/环境变量改，不再单独 CLI 参数

use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};

/// SRT-VPN 命令行参数
///
/// 版本号约定（2026-08-19 passwall 对接）：
/// - `-V / --version`：clap 自动生成，输出 "srt-vpn <version>"（短参数 -V 大写，与 -v 日志级别不冲突）
/// - passwall 组件更新（com.lua cmd_version）用 `-V | awk '{print $2}'` 解析出纯版本号（如 0.1.0）
#[derive(Parser, Debug, Clone)]
#[command(name = "srt-vpn", version, about = "基于 SRT 直播流协议的 VPN 隧道")]
pub struct Args {
    /// 配置文件路径（可选；省略时用 SRT_* 环境变量构建配置，Docker -e 场景）
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    pub config: Option<String>,

    /// 日志级别（0=ERROR, 1=WARN, 2=INFO, 3=DEBUG, 4=TRACE）
    /// 2026-08-19 审查修复：改为 Option<u8>（无默认值），以便区分
    /// "未指定 -v"（None，采用配置/环境变量）与"显式 -v 2"（Some(2)，覆盖配置）。
    #[arg(short = 'v', long = "verbose", value_name = "LEVEL")]
    pub verbose: Option<u8>,

    /// SOCKS5 监听地址（覆盖配置，如 127.0.0.1:1080）
    #[arg(long = "socks5-listen", value_name = "ADDR")]
    pub socks5_listen: Option<String>,

    /// SOCKS5 用户名（覆盖配置）
    #[arg(long = "socks5-user", value_name = "USER")]
    pub socks5_user: Option<String>,

    /// SOCKS5 密码（覆盖配置，注意：命令行明文，建议仅在测试环境使用）
    #[arg(long = "socks5-pass", value_name = "PASS")]
    pub socks5_pass: Option<String>,

    /// SOCKS5 多用户（可选，格式 user:pass,user2:pass2，覆盖配置）
    #[arg(long = "socks5-users", value_name = "USERS", action = ArgAction::Append)]
    pub socks5_users: Vec<String>,
}

/// 解析 CLI 参数（panic-free，错误时 clap 自动打印帮助并退出）
pub fn parse_args() -> Args {
    Args::parse()
}

/// UDP 模式枚举（服务端 -m 参数）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpMode {
    /// 可靠传输（SRT 自动重传，默认）
    Reliable,
    /// 尽力而为（不重传，低延迟）
    BestEffort,
}

impl UdpMode {
    /// 从字符串解析 UDP 模式
    pub fn parse_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "reliable" => Ok(Self::Reliable),
            "best-effort" | "besteffort" | "best_effort" => Ok(Self::BestEffort),
            other => Err(format!("无效的 UDP 模式 '{other}'（可选：reliable / best-effort）")),
        }
    }
}

/// 日志级别数值转字符串（用于日志初始化）
/// （当前 main.rs 直接用 verbose 数值，此方法预留）
#[allow(dead_code)]
impl Args {
    pub fn log_level_str(&self) -> &'static str {
        match self.verbose.unwrap_or(2) {
            0 => "error",
            1 => "warn",
            2 => "info",
            3 => "debug",
            _ => "trace",
        }
    }
}
