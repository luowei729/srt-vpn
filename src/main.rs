//! main.rs — SRT-VPN 入口
//!
//! 启动命令：
//!   srt-vpn -c server.conf   # 服务端（配置文件方式）
//!   srt-vpn -c client.json   # 客户端（配置文件方式）
//!   srt-vpn                  # 纯环境变量配置（Docker -e 场景，见 config::from_env）
//!
//! 职责：解析 CLI 参数 → 加载配置（文件或环境变量）→ 按模式分发到 server / client 模块
//!
//! 配置优先级：CLI 覆盖 > 环境变量(SRT_*) 覆盖 > 配置文件 > 默认值

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
    // 1. 解析 CLI 参数（-c 配置路径可选，-v 日志级别，-h 帮助）
    let args = cli::parse_args();

    // 2. 加载配置
    //    - 指定 -c：加载配置文件，再用环境变量(SRT_*)覆盖（Docker 场景可只改需要的参数）
    //    - 未指定 -c：纯环境变量构建配置（Docker -e 完整指定）
    let mut cfg = match &args.config {
        Some(path) => {
            let cfg = config::Config::load(path).unwrap_or_else(|e| {
                eprintln!("配置加载失败: {e}");
                std::process::exit(1);
            });
            // 配置文件为基础，环境变量覆盖（优先级：CLI > 环境变量 > 配置文件）
            let mut cfg = cfg;
            cfg.apply_env();
            cfg
        }
        None => {
            // 纯环境变量配置（SRT_MODE/SRT_PASSPHRASE 等必填项由 from_env 校验）
            config::Config::from_env().unwrap_or_else(|e| {
                eprintln!("环境变量配置加载失败: {e}");
                eprintln!("提示：可用 -c <配置文件> 指定配置文件，或用 SRT_* 环境变量配置");
                eprintln!("      SRT_MODE / SRT_PASSPHRASE 必填；服务端加 SRT_LISTEN，客户端加 SRT_SERVER");
                std::process::exit(1);
            })
        }
    };
    // 应用 CLI 参数覆盖（--socks5-* 优先级最高）
    cfg.apply_cli(&args);

    // 3. 初始化 JSON 结构化日志
    //    优先级：CLI -v > 配置 log_level（含环境变量 SRT_LOG_LEVEL）
    let verbose = if args.verbose != 2 {
        args.verbose // 用户显式指定了 -v
    } else {
        cfg.log_level.unwrap_or(args.verbose)
    };
    logging::init(verbose);

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
