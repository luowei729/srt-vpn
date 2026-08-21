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
| 8 | UDP 可靠性 | 配置文件 `udp_mode` 或环境变量 `SRT_UDP_MODE`（可靠默认/尽力而为），握手自动协商 |
| 9 | TS 伪装 | 标准 MPEG-TS 188B 分片；P1 固定 PID，P2 动态 PID |
| 10 | SOCKS5 | 用户名密码认证（多用户哈希存储，监听可配，CLI/环境变量可覆盖） |
| 11 | 挑战-应答 | streamid 静态令牌 + 首条消息双 HMAC（nonce+时间窗 30s 防重放） |
| 12 | 阶段划分 | P1 隧道核心+TS 伪装+TCP/UDP 代理+SOCKS5；P2 TUN+iptables NAT；P3 优化 |
| 13 | CLI 参数 | -c（可选，省略用 SRT_* 环境变量）/ -v / -h + SOCKS5 设定参数；优先级 CLI > 环境变量 > 配置文件 > 默认 |
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

### P1（已完成）：隧道核心 + 三合一代理 + UDP 代理

- [x] 设计树完成
- [x] Rust 项目骨架 + libsrt 构建集成
- [x] SRT FFI 封装层
- [x] 配置加载与 CLI
- [x] 多路复用层（会话路由 + 流控）
- [x] 挑战-应答认证（streamid 令牌 + 双 HMAC）
- [x] SOCKS5 + HTTP + HTTPS 三合一代理（首字节嗅探）
- [x] 服务器直连转发（TCP + UDP）
- [x] SOCKS5 UDP ASSOCIATE（UDP 隧道双向）
- [x] UDP 多目标 + 大包分片重组（>1301B 数据报支持）
- [x] 心跳 + 自动重连
- [x] 服务器稳定性加固（connect 超时 + 空闲看门狗）
- [x] 带宽优化（send_data_batch 同步投递、FileCC、多线程验证）
- [x] Docker 容器化 + GitHub Actions 手动发布（Alpine 镜像）

> 进度更新 2026-08-19：P1 全部完成并验证
> - 19 单元测试通过；本机回环下载 68MB/s、上传 76MB/s、8线程上传 92MB/s
> - 多线程上传原生支持（8/16/32 线程全成功）
> - UDP 代理（SOCKS5 UDP ASSOCIATE + 服务器 UDP 转发）已实现并回环验证双向通过
> - UDP 多目标 + 大包分片重组（100B/2048B/8000B 端到端回显一致）
> - 部署验证：新加坡 129.150.44.117（systemd contribs）、国内 47.102.196.219
> - Docker + CI 就绪（.github/workflows/release.yml 手动触发）

> 审查修复 2026-08-19（详见 CHANGELOG 12:00 条目）：
> - max_clients 计数泄漏修复（原子计数，任务结束释放）
> - 半关闭语义修复（会话通道改事件型 SessionEvent，Fin 投递不删会话）
> - 客户端整链自动重连（含 SOCKS5 serve 断开信号，缺此重连永不触发）
> - 主动心跳 + 死连接检测（此前 heartbeat_secs 配置未使用）
> - 客户端指标服务启动 + 指标字段接入（含 register_specific 计数一致性）
> - UDP 转发空闲看门狗、会话上限校验、会话 ID 分配边界修复
> - 测试 19 → 26 通过，release 零警告
> 审查修复 2026-08-19 15:00（第二轮，详见 CHANGELOG 15:00 条目）：
> - S 级 6 项：连接关闭链路重构（CAS 幂等+eid 归接收线程）、**断线状态值判断错误修复（SRTS_BROKEN=6，历史 CPU 79% 卡死真凶）**、退出段错误修复（atexit srt_cleanup + join 线程 + runtime 级联清理）、SOCKS5 监听失败死锁、认证窗口帧缓存回放（消除首个请求黑洞）、重连计数成功清零
> - H 级 5 项：UDP ASSOCIATE 泄漏（TCP 断开检测+看门狗）、UDP 域名/IPv6 目标全支持（服务端双栈 socket）、多用户 argon2 认证落地（users 表）、Open 冲突不再踢现有会话、rx_bytes 全路径计数
> - M 级 8 项：多客户端并行接入、nonce 一次性语义、重组器过期清理、日志优先级修正、UDP 回包来源锁定、max_clients 校验、可靠性协商标注 P2、心跳 RTT 指标（last_rtt_ms）
> - L 级：删冗余依赖/死模块（session.rs）、过时注释全面修正、重复函数收敛
> - 测试 25 通过，release 零警告；端到端 TCP/UDP 四类目标/断线重连 4 轮/退出安全全验证

> 修复扩展 2026-08-20（会话讣告 + 对时握手 + 内核调优，详见 CHANGELOG 03:05/03:25/05:30 条目）：
> - **会话死亡讣告**：任何会话退出路径统一发 Close/Rst（handle_open_with_rx 外层兜底 + 无法路由回 Rst），修复 WebRTC 多线程上传带宽暴跌（僵尸会话灌数据占满隧道）
> - **对时握手 v0.2.2**：CHALLENGE 携带服务端 ts，客户端用它算 HMAC（认证与本地时钟无关，根治软路由时钟漂移死循环）；时间窗 30->90s；双路径四象限兼容
> - **内核 UDP 缓冲**：部署服务器必须调 net.core.rmem_max≥32MB（默认 208KB 会钳制 SRTO_UDP_RCVBUF 导致缓冲溢出丢包重传风暴）
> - **公网对照实验结论**：单 SRT 连接 89 MB/s vs 4 连接并发 151 MB/s（+70%）-> 单连接共享 FileCC 窗口是并发瓶颈
> - **P1.5 方向（2026-08-20 06:13 最终拍板）**：**B 方案落地、A 方案放弃**。A 方案（单连接+复用层公平调度/流控，学 QUIC）编码验证回环 4 并发 302->36 MB/s（每 32KB 背压 await 开销过大），确认单连接共享 FileCC 窗口是物理天花板、应用层调度无法突破 -> 正式转向 B 方案（客户端维护 POOL_SIZE=4 条独立 SRT 连接，各自独立 FileCC 窗口，`pool.rs` 轮询分配会话）。回环 4 并发 302.8 MB/s、公网 4 并发 5.12 MB/s（~4.5x 于单连接 1.14，达直连链路 78%）。多连接代价是多 UDP 流（伪装从单流变多流），靠池大小平衡。

> 对接扩展 2026-08-19（passwall 集成，详见 CHANGELOG 17:55 条目）：
> - **静态二进制发布**：release.yml 新增 build-binaries（Alpine/musl 全静态 amd64/arm64）+ release（上传 Release assets）+ push v* tag 触发
> - **客户端域名支持**：resolve_addr（lookup_host 取 IPv4），passwall 节点地址可为域名
> - **SOCKS5 认证强制**：配置了认证时只接受 0x02 方法（has_auth 判定），修复认证可绕过漏洞
> - passwall 侧接入：组件更新（com.lua）+ 节点类型（7_srt-vpn.lua）+ app.sh srtvpn 分支 + util_srt-vpn.lua，见 openwrt-passwall-srt-vpn 仓库

### PX（重构，2026-08-20 启动）：Rust 自研 QUIC 语义内核 + 手写 SRT 全仿外壳

> 触发：libsrt 拥塞控制是单连接级单窗口（FileCC/LiveCC），多线程并发共享窗口，公网高 RTT 下单连接带宽结构性封顶，多轮无法根治。
> 决策经 grilling 盘问达成（详细设计见 docs/refactor/REFACTOR_PLAN_v3.md），用户已认可。

- [x] 盘问收敛共识（8 项决策锁定，见下节）
- [x] 设计文档产出（REFACTOR_PLAN_v3.md：协议字节草图 + 目录 + 里程碑）
- [x] **P0 内核+外壳（2026-08-20 09:55 完成）**：自研 quic/（varint/帧/多流/ACK/丢包/BBR）+ srt_shell/（0x80 握手 + 16B 头 + auth）；废弃 libsrt/build.rs；回环 + 多设备端到端验证通过
- [x] **P1 前端重建（部分完成）**：socks5/HTTP/UDP 重接新内核 + tunnel 保壳 + 多设备独立数据端口；UDP 待重验重、payload 加密待接线
- [x] **P1.5 传输层核心（2026-08-20 11:06 完成）**：载荷加解密接线（✓ send_raw/handle_datagram）+ 装饰 ACK 节奏（✓ make_ack_packet 接入 send_loop）+ **传输层三连修**（ACK 字节偏移语义/主流 offset 重组/吞吐三瓶颈，回环 1MB/s -> 下载 28/上传 14 MB/s，详见 CHANGELOG 11:06）
- [x] **P1.5 剩余**：乒乓心跳 RTT（ping/pong 接入）+ 多用户账号 + SACK/快速重传（公网丢包优化）+ POOL_SIZE 配置化
  - 乒乓心跳 RTT：✓ encode_ping/on_ping/on_pong 在 connection.rs 中已接入
  - 多用户账号：✓ socks5.rs validate_credential 支持 socks5_users 多用户 argon2 哈希表（SRT_SOCKS5_USERS 环境变量明文转哈希），端到端验证 3 用户+错误密码+不存在用户+无认证全正确
  - SACK/快速重传：✓ ack.rs on_ack 按完全 quic-go detectLostPackets（RFC9002 §7.3）重写：时间阈值 9/8 + 包号阈值 3 + lossTime 定时器
  - POOL_SIZE 配置化：✓ config.rs SRT_POOL_SIZE env + pool_size 配置项 + clamp 1..=16 默认 4（quic-go 无此概念，是 srt-vpn B 方案扩展）
- [x] **v0.4.0 推翻重做（2026-08-21 启动，传输层 v2 定版）**：自研 quic/srt_shell 全删，改用 `quinn-proto` 成熟 QUIC 状态机 + 自研 TUIC 协议层（~500 行）+ 包级 AES-128-CTR+SRT 0x80 外壳（双阶段密钥派生，线路上无 QUIC/TLS 明文）。**7 项血泪教训根治**（详见 CHANGELOG 2026-08-21 09:17）：
  单次 10M/100M 下载 53/52 MB/s、上传 40/47 MB/s，8 并发下载 1 唯一 MD5、4 并发上传 4/4 OK，30 单测+双端零告警。
- [ ] **P2 部署与 passwall**：passwall 适配新核心 + Docker/CI + 公网多线程 + SRT 特征抓包验证

### 重构共识决策表（grilling 收束，2026-08-20）

| # | 决策点 | 结论 |
|---|--------|------|
| A | 核心形态 | Rust 全盘自研，不依赖 libsrt / quiche / msquic |
| B | 传输内核 | 真 QUIC 语义（帧/多流/丢包补发/拥塞控制），**首包按 SRT 0x80、无 TLS 明文** |
| C | 外壳 | 手写 SRT 壳：0x80 握手 + 16B 头（SEQ/消息号/时间戳/ID）+ ACK 节奏 |
| D | libsrt | 彻底废弃（移除 build.rs/FFI/C 依赖） |
| E | 认证 | 学习 SRT 特征处理（拟真 libsrt 握手加密特征），**不保留现有双 HMAC** |
| F | 流控 | 单连接共享拥塞窗口（学 QUIC 流控即跑满带宽） |
| G | 前端 | socks5/HTTP/UDP 代理功能一致，复用现有分层接口 |
| H | passwall | 重构后按新核心再适配（不锁定旧套壳） |

### P2（规划：重构后更新）：TUN 模式 + iptables NAT + 动态 PID + 黑名单

> P2 原规划基于 libsrt 时代，待 PX 重构落地后按新内核重新评估 TUN/NAT/动态 PID 可行性。

### P3（规划）：性能 → 拟真 → 安全 → 跨平台打磨

---

*本文档将随项目开发持续更新，最新版本始终在 Git 仓库中。*
