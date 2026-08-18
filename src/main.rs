//! main.rs — SRT-VPN 入口
//!
//! 启动命令：
//!   srt-vpn -c server.conf   # 服务端
//!   srt-vpn -c client.json   # 客户端
//!
//! 职责：解析 CLI 参数 → 加载配置 → 按模式分发到 server / client 模块

mod auth;
mod cli;
mod client;
mod config;
mod logging;
mod metrics;
mod server;
mod srt;
mod tunnel;

#[tokio::main]
async fn main() {
    // 1. 解析 CLI 参数（-c 配置路径必选，-m UDP 模式，-v 日志级别，-h 帮助）
    let args = cli::parse_args();

    // 2. 初始化 JSON 结构化日志
    logging::init(args.verbose);

    // 3. 加载配置（server.conf / client.json，统一 JSON 语法，mode 字段区分角色）
    let mut cfg = config::Config::load(&args.config).unwrap_or_else(|e| {
        eprintln!("配置加载失败: {e}");
        std::process::exit(1);
    });
    // 应用 CLI 参数覆盖（-m / --socks5-* 优先级高于配置文件）
    cfg.apply_cli(&args);

    // 4. 按配置模式分发
    let result = match cfg.mode {
        config::Mode::Server => server::run(&cfg).await,
        config::Mode::Client => client::run(&cfg, &args).await,
    };

    // 5. 错误处理与退出码
    if let Err(e) = result {
        tracing::error!(error = %e, "程序运行失败");
        std::process::exit(1);
    }
}
