//! JSON 结构化日志模块
//!
//! 设计原因：passwall 通过 stdout 重定向收集日志（ln_run 的 >$log_file 2>&1），
//! 所以日志必须输出到 stdout。JSON 格式便于 passwall 或其他日志系统解析。
//! 容器日志大小由 Docker --log-opt 控制（详见 DOCKER.md）。

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// 初始化 JSON 结构化日志
///
/// # 参数
/// - `level_str`: 日志级别字符串（"info"/"debug"/"trace"/"warn"/"error"）
///
/// # 设计
/// 使用 tracing + tracing-subscriber，输出 JSON 格式到 stdout。
/// 优先级：环境变量 RUST_LOG > 参数 level_str > 默认 "info"。
pub fn init(level_str: &str) {
    // 解析日志级别，优先读环境变量 RUST_LOG，无则用传入参数
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level_str));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .json() // JSON 格式，便于日志系统解析
                .with_target(true) // 包含模块路径
                .with_thread_ids(false) // 不含线程 ID（减少日志量）
                .with_file(false) // 不含源码文件名（减少日志量）
                .with_line_number(false), // 不含行号（减少日志量）
        )
        .init();
}
