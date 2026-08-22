//! main.rs - SRT-VPN 入口
//!
//! 启动命令：
//!   srt-vpn -c server.conf   # 服务端（配置文件方式）
//!   srt-vpn -c client.json   # 客户端（配置文件方式）
//!   srt-vpn                  # 纯环境变量配置（Docker -e 场景，见 config::from_env）
//!
//! 职责：解析 CLI 参数 -> 加载配置（文件或环境变量）-> 按模式分发到 server / client 模块
//!
//! 配置优先级：CLI 覆盖 > 环境变量(SRT_*) 覆盖 > 配置文件 > 默认值
//!
//! S6 修复（2026-08-19）：退出路径安全化。
//! 旧实现在失败时直接 process::exit(1) -- 跳过 tokio runtime Drop ->
//! 连接对象不清理 -> atexit(srt_cleanup) 停 GC 线程时与仍在运行的收发线程
//! 竞态 -> 退出段错误（实测 CRcvQueue::worker 崩溃 exit 139）。
//! 新结构：async_main 记录失败码到 EXIT_CODE -> runtime Drop 级联清理
//! （任务 Drop -> 连接 Drop -> close() join 收发线程）-> 最后才按码退出。

mod auth;
mod cli;
mod client;
mod config;
mod logging;
mod metrics;
mod server;
mod srt;
mod tunnel;

/// 进程退出码（S6：跨 runtime Drop 传递失败状态）
static EXIT_CODE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

fn main() {
    // 手工构建 runtime（等价 #[tokio::main]，但能在 Drop 后执行退出逻辑）：
    // 1. runtime 运行 async_main（失败时记录码到 EXIT_CODE）
    // 2. runtime Drop -> 所有任务与连接 Drop -> close() join 收发线程
    // 3. 最后按 EXIT_CODE 退出（atexit 的 srt_cleanup 不会再与线程竞态）
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime 构建失败");
    rt.block_on(async_main());
    drop(rt);
    let code = EXIT_CODE.load(std::sync::atomic::Ordering::Acquire);
    if code != 0 {
        std::process::exit(code);
    }
}

/// 异步主逻辑（配置加载 + 分发），失败记录退出码
async fn async_main() {
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
    //    优先级：CLI -v（显式指定，含 -v 2）> 配置 log_level（含环境变量 SRT_LOG_LEVEL）> 默认 2
    //    2026-08-19 审查修复：verbose 改 Option<u8>，区分"未指定"与"显式 -v 2"，
    //    使 -v 2 也能显式覆盖配置文件里的 log_level（原逻辑 args.verbose != 2 视为未指定）。
    let verbose = match args.verbose {
        Some(v) => v, // 用户显式指定了 -v（任意值均可覆盖配置/环境变量）
        None => cfg.log_level.unwrap_or(2), // 未指定：用配置 log_level（或默认 2）
    };
    logging::init(verbose);

    // 4. 按配置模式分发
    let result = match cfg.mode {
        config::Mode::Server => server::run(&cfg).await,
        config::Mode::Client => client::run(&cfg, &args).await,
    };

    // 5. 错误处理（记录退出码；真正的退出在 runtime Drop 之后，见 main）
    if let Err(e) = result {
        tracing::error!(error = %e, "程序运行失败");
        EXIT_CODE.store(1, std::sync::atomic::Ordering::Release);
    }
}
