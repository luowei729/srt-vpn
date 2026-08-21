//! SRT-VPN 主入口
//!
//! 项目: SRT 外壳伪装 + quinn-proto QUIC 内核 + TUIC 协议语义 VPN
//! 版本: 0.4.0 (2026-08-21 重构)
//!
//! 架构: TUIC 协议层 + quinn-proto 传输内核 + SRT 深度仿真外壳 + 包级 AES 加密
//! 线路上只看到 SRT 壳 + 密文，DPI 看不到 QUIC/TLS 明文特征。

mod cli;
mod client;
mod config;
mod logging;
mod metrics;
mod server;
mod transport;
mod tuic;

use clap::Parser;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // 安装 rustls CryptoProvider（rustls 0.23+ 需要显式选择）
    // 使用 aws-lc-rs 后端（quinn-proto 默认依赖）
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("安装 rustls CryptoProvider 失败");

    // 1. 解析 CLI 参数
    let args = cli::Cli::parse();

    // 2. 加载配置（-c 文件 或 纯环境变量）
    let config = match args.config {
        Some(ref path) => config::Config::from_file(path),
        None => config::Config::from_env(),
    };

    let config = match config {
        Ok(c) => c,
        Err(e) => {
            eprintln!("配置错误: {}", e);
            std::process::exit(1);
        }
    };

    // 3. 初始化日志（JSON → stdout）
    // CLI -v 优先级最高
    let log_level = match args.verbose {
        0 => config.log_level.clone(),
        1 => "warn".to_string(),
        2 => "info".to_string(),
        3 => "debug".to_string(),
        _ => "trace".to_string(),
    };
    logging::init(&log_level);

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "srt-vpn 启动");

    // 4. 启动指标服务
    let metrics = Arc::new(metrics::Metrics::new());
    if config.metrics_port > 0 {
        let m = metrics.clone();
        tokio::spawn(async move {
            metrics::serve(m, config.metrics_port).await;
        });
    }

    // 5. 根据模式分发
    match config.mode {
        cli::Mode::Server => {
            tracing::info!("启动服务端模式");
            server::run(config, metrics).await;
        }
        cli::Mode::Client => {
            tracing::info!("启动客户端模式");
            client::run(config, metrics).await;
        }
    }
}
