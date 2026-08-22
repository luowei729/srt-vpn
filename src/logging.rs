//! logging.rs — JSON 结构化日志初始化
//!
//! 设计决策（Q22）：JSON 结构化日志（tracing-subscriber json 格式）
//! - 输出到 stdout（生产用 systemd/journald 采集）
//! - 级别由 -v 控制（0=ERROR, 1=WARN, 2=INFO, 3=DEBUG, 4=TRACE）

use tracing_subscriber::EnvFilter;

/// 初始化 JSON 结构化日志
/// verbose: 0-4（对应 error/warn/info/debug/trace）
///
/// M4 修复（2026-08-19）：不再读 RUST_LOG 环境变量。
/// 旧实现 EnvFilter::try_from_default_env() 优先级高于 -v CLI 参数，
/// 只要环境里残留 RUST_LOG 就静默覆盖用户显式指定的日志级别，
/// 违背"CLI > 环境变量 > 配置文件"的优先级承诺。
/// 现日志级别只由调用方（main.rs 已按 CLI>配置 优先级解析出的 verbose）决定。
pub fn init(verbose: u8) {
    // 将 verbose 数值映射为日志级别字符串
    let level = match verbose {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    // 过滤器（M4：显式构造，不读 RUST_LOG；SRT 库日志经 log 桥接输出）
    let filter = EnvFilter::new(format!("srt_vpn={level},srt_vpn::srt={level}"));

    // JSON 格式输出到 stdout，附时间戳
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
