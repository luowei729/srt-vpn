# ============================================================
# SRT-VPN 容器化构建（多阶段，Alpine 基础镜像）
#
# 2026-08-20 重构：纯 Rust 项目（libsrt 已废弃），构建无需
#   cmake / openssl-dev / linux-headers / build.rs / srt-1.5.6。
#   运行为 musl 静态链接，无外部动态依赖库。
# ============================================================

# ---- 阶段1：编译（Alpine，musl 静态链接）----
FROM rust:1.97-alpine AS builder

WORKDIR /build

# 拷贝清单（最大化缓存）
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/

# 编译 release（纯 Rust，静态 musl）
RUN cargo build --release

# ---- 阶段2：运行时（Alpine）----
FROM alpine:3.20 AS runtime

# 非 root 运行
RUN adduser -D -u 1000 srtvpn

WORKDIR /app

# 拷贝编译产物（musl 静态可执行，无动态依赖）
COPY --from=builder /build/target/release/srt-vpn /usr/local/bin/srt-vpn

# 默认配置文件目录（挂载点）
RUN mkdir -p /app/configs && chown -R srtvpn:srtvpn /app

USER srtvpn

# 默认入口：无参数直接运行（纯环境变量配置）
ENTRYPOINT ["/usr/local/bin/srt-vpn"]
# CMD 为空：docker run 不带命令时直接跑主程序（纯环境变量启动）
CMD []
