//! build.rs — 构建脚本：编译 libsrt 1.5.6 官方源码为静态库并链接进 Rust 二进制
//!
//! 设计原因：
//! - libsrt 官方源码位于 srt-1.5.6/（不动它），本脚本用 CMake 生成静态库
//! - 静态链接保证部署无动态依赖（libsrt.so 不依赖系统安装）
//! - OpenSSL 作为加密后端（系统已装 openssl 头文件）
//! - 通过 cargo:rustc-link-lib 把 libsrt 静态库链接进最终二进制

use std::path::PathBuf;
use std::process::Command;
fn main() {
    // 1. 定位 libsrt 源码目录（相对当前 Cargo.toml 所在目录）
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let srt_src = manifest_dir.join("srt-1.5.6");
    if !srt_src.join("CMakeLists.txt").exists() {
        panic!("未找到 libsrt 源码: {}", srt_src.display());
    }

    // 2. 构建目录（放在 target 下的独立目录，避免污染源码树）
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR 未设置"));
    let build_dir = out_dir.join("srt-build");
    std::fs::create_dir_all(&build_dir).expect("创建 srt 构建目录失败");

    // 3. 配置 CMake：静态库 + 不构建官方应用（srt-live-transmit 等不需要）
    //    ENABLE_APPS=OFF 跳过官方 app 编译，减少构建时间
    //    ENABLE_ENCRYPTION=ON 启用 SRT 原生加密（passphrase）
    //    CMAKE_BUILD_TYPE=Release 优化性能
    let configure_status = Command::new("cmake")
        .arg("-S")
        .arg(&srt_src)
        .arg("-B")
        .arg(&build_dir)
        .arg("-DENABLE_APPS=OFF")
        .arg("-DENABLE_ENCRYPTION=ON")
        .arg("-DENABLE_SHARED=OFF")
        .arg("-DENABLE_STATIC=ON")
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .status()
        .expect("cmake configure 失败（请确认系统已安装 cmake）");
    assert!(configure_status.success(), "cmake configure 返回非零状态");

    // 4. 编译 libsrt 静态库
    let build_status = Command::new("cmake")
        .arg("--build")
        .arg(&build_dir)
        .arg("--target")
        .arg("srt_static")
        .arg("-j")
        .arg(num_cpus())
        .status()
        .expect("cmake build 失败");
    assert!(build_status.success(), "cmake build 返回非零状态");

    // 5. 输出链接指令：告诉 cargo 链接 libsrt 静态库和其依赖（OpenSSL）
    //    libsrt 是 C++ 库：需要 libstdc++（operator new/delete 等符号）
    //    libsrt 依赖 OpenSSL（crypto+ssl），需显式链接
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=srt");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=ssl");
    // 注意：Alpine/musl 中 pthread 是 libc 内置，无需（也不能）单独链接；
    // glibc 环境才需要 -lpthread。按 TARGET 原生支持判定（Docker Alpine 场景关键）。
    if target_has_libpthread() {
        println!("cargo:rustc-link-lib=pthread");
    }
    println!("cargo:rustc-link-lib=m");

    // 6. 让 cargo 感知源码变化（源码改动时自动触发重编译）
    println!("cargo:rerun-if-changed={}", srt_src.display());
}

/// 判断当前编译目标是否需要显式链接 libpthread
/// - glibc（标准 Linux / Debian / 本机）：需要 -lpthread
/// - musl（Alpine）：pthread 已并入 libc，单独链接会报"无法找到 -lpthread"或产生
///   冗余 stub；返回 false 跳过
fn target_has_libpthread() -> bool {
    let target = std::env::var("TARGET").unwrap_or_default();
    // musl 目标（如 x86_64-unknown-linux-musl / aarch64-unknown-linux-musl）
    !target.contains("musl")
}

/// 获取可用 CPU 核数（限制最大并行度，避免 OOM）
fn num_cpus() -> String {
    std::thread::available_parallelism()
        .map(|n| n.get().min(8).to_string())
        .unwrap_or_else(|_| "4".to_string())
}
