//! logging.rs — JSON 结构化日志初始化
//!
//! 设计决策（Q22）：JSON 结构化日志（tracing-subscriber json 格式）
//! - 输出到 stdout（生产用 systemd/journald 采集）
//! - 级别由 -v 控制（0=ERROR, 1=WARN, 2=INFO, 3=DEBUG, 4=TRACE）

use tracing_subscriber::EnvFilter;

/// 初始化 JSON 结构化日志
/// verbose: 0-4（对应 error/warn/info/debug/trace）
pub fn init(verbose: u8) {
    // 将 verbose 数值映射为日志级别字符串
    let level = match verbose {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    // 构造过滤器（允许覆盖：SRT 库的日志通过 log 桥接输出）
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("srt_vpn={level},srt_vpn::srt={level}")));

    // JSON 格式输出到 stdout，附时间戳
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
