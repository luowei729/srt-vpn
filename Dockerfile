# ============================================================
# SRT-VPN 容器化构建（多阶段，Alpine 基础镜像）
#
# 为什么用 Alpine：
#   - 镜像极小（基础镜像 ~5MB，整个镜像 <50MB vs Debian ~150MB）
#   - 启动快、内存占用低（VPN 常驻进程适合）
#   - libsrt 静态链接进二进制，运行只需 libstdc++ + openssl
#
# 阶段1 builder：在 Alpine 内编译 libsrt + Rust（必须同环境编译，
#               因为 Alpine 是 musl libc，不能用 Debian 的二进制）
# 阶段2 runtime：精简 Alpine 运行镜像
# ============================================================

# ---- 阶段1：编译（Alpine）----
FROM rust:1.97-alpine AS builder

# 编译工具：build-base（gcc/g++/make）+ cmake + openssl 头
# libsrt 是 C++，需要 g++；Rust 链接 libstdc++
# linux-headers：libsrt 源码 srtcore/socketconfig.h 包含 <linux/if.h>，
#                缺省会报 "linux/if.h: No such file or directory"（2026-08-19 CI 踩坑）
# openssl-libs-static：Rust musl 默认 -Wl,-Bstatic 链接 OpenSSL，必须用静态库；
#                只有 openssl-dev（.so stub）会报 "cannot find -lcrypto"（2026-08-19 CI 踩坑）
RUN apk add --no-cache \
    build-base \
    cmake \
    openssl-dev \
    openssl-libs-static \
    linux-headers \
    pkgconfig

WORKDIR /build

# 拷贝清单与构建脚本（最大化缓存）
COPY Cargo.toml Cargo.lock build.rs ./
COPY srt-1.5.6/ ./srt-1.5.6/
COPY src/ ./src/

# 编译 release（libsrt 静态库 + Rust 二进制）
RUN cargo build --release

# ---- 阶段2：运行时（Alpine）----
FROM alpine:3.20 AS runtime

# 运行依赖：libstdc++（SRT 是 C++ 库）、openssl（SRT 加密）、ca-certificates、
#           tzdata（日志时区）
RUN apk add --no-cache \
    libstdc++ \
    openssl \
    ca-certificates \
    tzdata

# 非 root 运行
RUN adduser -D -u 1000 srtvpn

WORKDIR /app

# 拷贝编译产物
COPY --from=builder /build/target/release/srt-vpn /usr/local/bin/srt-vpn

# 默认配置文件目录（挂载点）
RUN mkdir -p /app/configs && chown -R srtvpn:srtvpn /app

USER srtvpn

# 默认入口：查看帮助；实际使用用 -e SRT_* 环境变量配置（无需挂载配置文件）
# 示例（服务端）：
#   docker run -d --net=host \
#     -e SRT_MODE=server \
#     -e SRT_PASSPHRASE=your-passphrase \
#     -e SRT_LISTEN=0.0.0.0:9000 \
#     srt-vpn:latest
# 示例（客户端）：
#   docker run -d -p 1080:1080 \
#     -e SRT_MODE=client \
#     -e SRT_PASSPHRASE=your-passphrase \
#     -e SRT_SERVER=server-ip:9000 \
#     -e SRT_SOCKS5_LISTEN=0.0.0.0:1080 \
#     srt-vpn:latest
ENTRYPOINT ["/usr/local/bin/srt-vpn"]
CMD ["--help"]
