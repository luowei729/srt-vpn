# SRT-VPN 项目开发方案

> 版本: v1.0
> 创建日期: 2026-08-18 (北京时间)
> 状态: **设计完成，开始 P1 开发**

---

## 一、项目概述

### 1.1 项目定位

SRT-VPN 是一个基于 SRT（Secure Reliable Transport）直播流协议的 VPN 项目，利用 SRT 协议的流量特征（握手、ACK/NACK 重传、UDP 底层）实现隐蔽的数据隧道。流量伪装为"SRT 直播流"，具备标准 MPEG-TS 媒体帧特征。

### 1.2 启动命令

```
srt-vpn -c server.conf     # 服务端
srt-vpn -c client.json     # 客户端
```

### 1.3 开发语言

- Rust（主开发语言，异步 tokio 运行时）
- C（libsrt 1.5.6 官方源码静态编译 + Rust FFI 封装）

---

## 二、已确认的架构决策（设计树结论）

| # | 决策点 | 结论 |
|---|--------|------|
| 1 | 核心形态 | 完整 VPN：TUN 全接管 + SOCKS5 服务接口 + 端口转发模式 |
| 2 | SRT 数据平面 | 官方 libsrt 1.5.6 静态库 + Rust FFI（OpenSSL 后端，GCC 编译） |
| 3 | 流量伪装 | 深度伪装：数据先加密 → 标准 MPEG-TS 188B 分片 → SRT 发送 |
| 4 | 加密认证 | SRT passphrase 原生加密（默认 aes-128，可配 192/256）+ 双 HMAC 挑战-应答 |
| 5 | 传输层 | SRT 跑在 UDP 底层；TCP/UDP 流量都代理（TCP 转封装进 UDP/SRT 通道） |
| 6 | 配置文件 | 统一 JSON 语法（serde），文件名保持 server.conf / client.json |
| 7 | 隧道复用 | 单 SRT 连接 + 自研多路复用层（256 会话，u16 会话 ID，帧头版本 v1） |
| 8 | UDP 可靠性 | -m 服务端配置（可靠默认/尽力而为），握手自动协商 |
| 9 | TS 伪装 | 标准 MPEG-TS 188B 分片；P1 固定 PID，P2 动态 PID |
| 10 | SOCKS5 | 用户名密码认证（多用户哈希存储，监听可配，CLI 可覆盖） |
| 11 | 挑战-应答 | streamid 静态令牌 + 首条消息双 HMAC（nonce+时间窗 30s 防重放） |
| 12 | 阶段划分 | P1 隧道核心+TS 伪装+TCP/UDP 代理+SOCKS5；P2 TUN+iptables NAT；P3 优化 |
| 13 | CLI 参数 | -c / -m / -v / -h + SOCKS5 完整设定参数 |
| 14 | 可靠性模型 | 单层可靠：可靠传输交给 SRT 层，复用层只做分帧+调度+窗口流控 |
| 15 | 端口策略 | 单端口（数据+信号共存） |
| 16 | 心跳保活 | 5s 心跳 + 客户端自动重连 |
| 17 | 服务器出口 | P1 直连转发；P2 iptables masquerade + ip_forward |
| 18 | TCP 语义 | P1 支持半关闭（单向 FIN 传播） |
| 19 | 平台 | 客户端跨平台（Linux/Win/macOS，tun2 crate）；服务器仅 Linux |
| 20 | 多客户端 | 服务器支持多客户端并发，每客户端独立会话空间 |
| 21 | 线程模型 | tokio 异步 + SRT 事件循环线程 |
| 22 | 日志监控 | JSON 结构化日志 + 回环 HTTP 指标端口 |
| 23 | 交付物 | 单二进制 + 配置样例 + systemd 样例 + ffprobe/ffmpeg 验证脚本 |
| 24 | 目录规划 | 保留 srt-1.5.6/，根目录建 Rust 项目 |

---

## 三、系统架构

### 3.1 全局架构图

```
┌──────────────────────────────┐          ┌──────────────────────────────┐
│         客户端 (Linux/Win/mac)│          │      服务器 (仅 Linux)        │
│                              │          │                              │
│  ┌──────────┐  ┌──────────┐  │  SRT/UDP  │  ┌──────────┐  ┌──────────┐  │
│  │ SOCKS5   │  │  TUN(P2) │  │◄────────►│  │ 直连转发  │  │NAT(P2)   │  │
│  │ 入口      │  │  入口     │  │  伪装TS流  │  │ (P1)     │  │          │  │
│  └────┬─────┘  └────┬─────┘  │          │  └────┬─────┘  └────┬─────┘  │
│       │             │        │          │       │             │        │
│  ┌────▼─────────────▼─────┐  │          │  ┌────▼─────────────▼─────┐  │
│  │    多路复用层 (会话ID)   │  │          │  │    多路复用层 (会话ID)   │  │
│  │  分帧+调度+窗口流控      │  │          │  │  分帧+调度+窗口流控      │  │
│  └───────────┬────────────┘  │          │  └───────────┬────────────┘  │
│  ┌───────────▼────────────┐  │          │  ┌───────────▼────────────┐  │
│  │  TS 伪装层 (188B 分片)   │  │          │  │  TS 伪装层 (188B 分片)   │  │
│  │  MPEG-TS + 加密          │  │          │  │  MPEG-TS + 加密         │  │
│  └───────────┬────────────┘  │          │  └───────────┬────────────┘  │
│  ┌───────────▼────────────┐  │          │  ┌───────────▼────────────┐  │
│  │ SRT FFI (libsrt 静态库)  │  │          │  │ SRT FFI (libsrt 静态库)  │  │
│  └───────────┬────────────┘  │          │  └───────────┬────────────┘  │
│  ┌───────────▼────────────┐  │          │  ┌───────────▼────────────┐  │
│  │      UDP Socket        │  │          │  │      UDP Socket        │  │
│  └────────────────────────┘  │          │  └────────────────────────┘  │
└──────────────────────────────┘          └──────────────────────────────┘
```

### 3.2 多路复用层协议（v1）

```
┌──────────────┬──────────────┬──────────────┬────────────────────────┐
│ Magic (4B)   │ Version (1B) │ Type (1B)    │ Session ID (u16 BE)    │
├──────────────┼──────────────┼──────────────┼────────────────────────┤
│ 长度 (u16 BE) │ 序号 (u32 BE) │ 标志位 (1B)   │ Payload (可变)          │
└──────────────┴──────────────┴──────────────┴────────────────────────┘
```

- Type: DATA / ACK / NACK / CHALLENGE / RESPONSE / HEARTBEAT / OPEN / CLOSE / FIN
- 标志位: FIN(0x01) / RST(0x02) / RELIABLE(0x04) / 窗口更新(0x08)
- 所有帧（含 ACK）统一封装进 TS 188B 包，保证抓包全为 TS 结构

### 3.3 TS 伪装层

- 标准 MPEG-TS 包：同步字节 0x47 + 188 字节固定长度
- P1 固定 PID（如 0x0100 视频），P2 动态 PID
- 封装顺序：数据 → 加密 → TS 分片（TS 壳透明可读，内容加密不可读）
- 加密算法：SRT passphrase 原生 AES-GCM（链路级）

### 3.4 挑战-应答认证流程

```
客户端                                  服务器
  │  streamid: #!::r=live/srtvpn,m=video,k=令牌(HMAC-SHA256(passphrase,盐))
  │──────────────────────────────────────►│  校验令牌
  │◄──────────────────────────────────────│  CHALLENGE: nonce (随机数)
  │  RESPONSE: HMAC-SHA256(passphrase, nonce+时间戳)  │  校验应答+时间窗30s
  │──────────────────────────────────────►│  通过 → 建立会话空间
```

---

## 四、项目结构

```
srt-vpn/
├── Cargo.toml                  # Rust 项目配置（workspace）
├── srt-1.5.6/                  # libsrt 官方源码（构建时静态编译）
├── src/
│   ├── main.rs                 # 入口：CLI 解析 + 模式分发
│   ├── config.rs               # 配置加载（serde JSON）
│   ├── cli.rs                  # CLI 参数解析（clap）
│   ├── srt/                    # SRT FFI 封装
│   │   ├── mod.rs
│   │   ├── bindings.rs         # unsafe FFI 声明
│   │   └── connection.rs       # 连接管理（事件循环线程）
│   ├── tunnel/                 # 隧道层
│   │   ├── mod.rs
│   │   ├── multiplex.rs        # 多路复用层（分帧/调度/流控）
│   │   ├── ts.rs               # TS 伪装层（188B 分片）
│   │   └── session.rs          # 会话管理（256 上限）
│   ├── auth/                   # 认证
│   │   ├── mod.rs
│   │   └── challenge.rs        # 双 HMAC 挑战-应答
│   ├── client/                 # 客户端
│   │   ├── mod.rs
│   │   ├── socks5.rs           # SOCKS5 入口（用户名密码认证）
│   │   └── proxy.rs            # 代理逻辑（TCP/UDP → 隧道）
│   ├── server/                 # 服务器
│   │   ├── mod.rs
│   │   ├── listener.rs         # 多客户端监听
│   │   └── forward.rs          # 直连转发出口
│   ├── metrics.rs              # 运行指标（回环 HTTP）
│   └── logging.rs              # JSON 日志
├── build.rs                    # 构建脚本（编译 libsrt 静态库）
├── configs/
│   ├── server.conf             # 服务端示例配置
│   └── client.json             # 客户端示例配置
├── deploy/
│   └── srt-vpn.service         # systemd 服务样例
├── scripts/
│   └── verify_ts.sh            # ffprobe 验证伪装真实性
└── docs/
    └── PROTOCOL.md             # 协议细节文档
```

---

## 五、配置示例

### 5.1 server.conf（JSON 内容）

```json
{
  "mode": "server",
  "listen": "0.0.0.0:9000",
  "passphrase": "your-passphrase",
  "crypto": "aes-128",
  "udp_mode": "reliable",
  "max_clients": 32,
  "socks5_users": [
    {"username": "user1", "password_hash": "argon2:$v=19$..."}
  ],
  "metrics_port": 9090
}
```

### 5.2 client.json

```json
{
  "mode": "client",
  "server": "vpn.example.com:9000",
  "passphrase": "your-passphrase",
  "crypto": "aes-128",
  "streamid": "#!::r=live/srtvpn,m=video",
  "socks5": {
    "listen": "127.0.0.1:1080",
    "username": "user1",
    "password": "password123"
  },
  "reconnect": {"interval_secs": 5, "max_retries": 10},
  "metrics_port": 9091
}
```

---

## 六、开发阶段

### P1（当前）：隧道核心 + TS 伪装 + TCP/UDP 代理 + SOCKS5

- [x] 设计树完成
- [x] Rust 项目骨架 + libsrt 构建集成
- [x] SRT FFI 封装层
- [x] 配置加载与 CLI
- [x] 多路复用层（TS 伪装 + 流控 + 会话）
- [x] 挑战-应答认证（链路打通：streamid 令牌 + 双 HMAC）
- [ ] SOCKS5 客户端入口（骨架已建，需接入隧道数据转发）
- [ ] 服务器直连转发（骨架已建，需接入数据路由）
- [ ] 心跳 + 重连（骨架已建，需周期发送）
- [ ] 联调 + 验证脚本

> 进度更新 2026-08-18 15:45：编译零警告、15 单元测试通过、认证链路端到端打通。
> 待完成：隧道数据帧路由 + SOCKS5 真实认证 + 转发联调。

### P2：TUN 模式 + iptables NAT + 动态 PID + 黑名单

### P3：性能 → 拟真 → 安全 → 跨平台打磨

---

*本文档将随项目开发持续更新，最新版本始终在 Git 仓库中。*
