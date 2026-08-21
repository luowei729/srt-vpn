# SRT-VPN 重构设计 v4（TUIC 协议语义 + quinn-proto 内核 + SRT 外壳）

> 版本：v0.4.0 设计（2026-08-21 北京时间）
> 状态：**共识确认，开始实施**
> 前置：grilling 盘问四轮收束（2026-08-21）

---

## 一、背景与动机

### 1.1 为什么再次重构

v0.3.x 自研 QUIC 语义传输内核（`src/quic/`）+ 手写 SRT 外壳（`src/srt_shell/`）
经多轮修复（ACK 语义、队头阻塞、吞吐瓶颈、CUBIC 拥控、丢包恢复、连接池、
断线保活等）仍无法根治稳定性问题。

**核心矛盾**：自研传输层缺乏生产级成熟度。QUIC 的拥塞控制 / 丢包恢复 /
流控等复杂状态机难以手工正确实现——即使参照 quic-go 源码移植，仍有大量
边界条件和竞态问题。

### 1.2 新方案核心思路

**用成熟 QUIC 库（quinn-proto）做传输内核，自研仅做协议层 + SRT 伪装外壳。**

- `quinn-proto`：Cloudflare/微软维护的成熟 QUIC 状态机（无 I/O），生产级可靠性
- TUIC 协议层：从零参照实现（~500 行），传输无关的协议编解码
- SRT 伪装：I/O 薄层做包级 AES-128-CTR 加密后套 SRT 0x80 外壳
- **线路上只看到 SRT 壳 + 密文**，DPI 看不到 QUIC/TLS 明文特征

### 1.3 关键架构判断

标准 QUIC 库（quinn/quiche/s2n-quic/tquic）的首包都是 `0xC0` + TLS 1.3
ClientHello 明文——这是 QUIC 协议不可去除的指纹。但用 `quinn-proto`（无 I/O
状态机）+ 自管 UdpSocket，可以在 I/O 层做**包级加密**：quinn-proto 生成的
QUIC 包（含 ClientHello）被整体 AES-128-CTR 加密后套 SRT 0x80 外壳发送。
QUIC 握手在 quinn-proto 内部正常发生（保证传输可靠性），但线路上看不到
任何 QUIC 明文。

---

## 二、共识清单（盘问收束，2026-08-21）

| # | 决策点 | 结论 |
|---|--------|------|
| 1 | 传输层 | quinn-proto（成熟 QUIC 状态机，无 I/O）+ 自管 UdpSocket |
| 2 | 协议层 | TUIC 协议语义从零参照实现（~500 行，不引入 wind 框架） |
| 3 | 代码范围 | 全部删除，从空项目重新开始 |
| 4 | 代理功能 | TUIC SOCKS5 核心 + HTTP 代理薄层，三合一同端口 |
| 5 | 连接模型 | 单 QUIC 连接 stream 多路复用，无连接池 |
| 6 | SRT 外壳 | 深度仿真：握手 0x80 + 数据头 + ACK 节奏 |
| 7 | 认证 | TUIC 原版：UUID+password → TLS exporter（RFC5705）token |
| 8 | 多用户 | 服务端 HashMap<Uuid, String>，每用户独立认证 |
| 9 | UDP 模式 | 流模式（可靠）：走 QUIC 双向流 |
| 10 | 配置 schema | TUIC 原生字段名（uuid/password/server/socks5） |
| 11 | 项目名 | 保持 srt-vpn（passwall 已硬编码命名） |
| 12 | I/O 驱动 | tokio 桥接（select! 包 socket+定时器+事件） |
| 13 | SRT 壳位置 | I/O 薄层封装（poll_transmit 后加壳，recv_from 后去壳） |
| 14 | 包级加密 | quinn-proto 输出 QUIC 包整体 AES-128-CTR 加密后套 SRT 头 |
| 15 | 密钥派生 | 双阶段：passphrase→临时密钥(首包) → TLS exporter→会话密钥 |
| 16 | CLI | -c/-V/-h（保持 passwall 契约） |
| 17 | 部署 | 保留 Dockerfile + release.yml 框架 |
| 18 | 开发顺序 | 传输层→协议层→客户端→服务端→Docker/CI→passwall |
| 19 | 验收 | 回环≥100MB/s、2%/5%丢包一致、镜像<50MB、passwall可用 |

---

## 三、线协议设计

### 3.1 外层：SRT 全仿壳（每 UDP 数据报）

```
┌── SRT 壳 16B 固定头 ──────────────────────────────────────────┐
│ 0-3   SEQNO:   bit31=0 数据 / =1 控制；bit30..16=消息类型；   │
│                bit15..0=扩展                                    │
│ 4-7   MSGNO:   bit31-30 边界；bit29 顺序；bit28-27 key 标志；  │
│                bit26 重传；bit25-0 消息序号                    │
│ 8-11  TIMESTAMP: 32 位微秒时间戳                               │
│ 12-15 ID:       目标 socket ID                                 │
├── 内层：AES-128-CTR 密文 ────────────────────────────────────┤
│ [加密后的 QUIC 包（含 TLS ClientHello/握手/数据/ACK）]         │
└───────────────────────────────────────────────────────────────┘
```

- 握手首包：控制包 bit31=1 + 类型=HANDSHAKE(0) → 首 4B `0x80 00 00 00`
- ACK 包：控制包 + 类型=ACK(2) → 首 4B `0x80 02 00 00`
- 数据包：bit31=0 → 首 4B `0x00..0x7f`

### 3.2 内层：TUIC 协议帧

TUIC 命令（VER=0x05，2 字节包头 `[VER][CMD]`）：

```
Auth:       [0x05][0x00][uuid 16B][token 32B]     共 50B（走 QUIC uni-stream）
Connect:    [0x05][0x01][Address]                   走 QUIC bi-stream
Packet:     [0x05][0x02][assoc_id 2B][pkt_id 2B]
            [frag_total 1B][frag_id 1B][size 2B][Address][payload]
Dissociate: [0x05][0x03][assoc_id 2B]
Heartbeat:  [0x05][0x04]                            走 QUIC datagram 或 bi-stream
```

### 3.3 双阶段密钥派生

**阶段 1（TLS 握手前）**：
- 用 passphrase 经 PBKDF2 派生临时 AES-128 密钥
- 加密 quinn-proto 生成的 Initial 包（含 ClientHello）
- 套 SRT 握手壳发送

**阶段 2（TLS 握手完成后）**：
- `conn.crypto_session().export_keying_material(output, label, context)`
- label = UUID 字符串，context = password
- 派生 32B → 取前 16B 作为 AES-128-CTR 会话密钥
- 替换临时密钥加密后续包

---

## 四、目录结构

```
srt-vpn/
├── Cargo.toml              # quinn-proto, rustls, tokio, bytes, uuid, aes, clap
├── src/
│   ├── main.rs             # 入口: CLI 解析 + 模式分发
│   ├── cli.rs              # clap: -c/-V/-h
│   ├── config.rs           # JSON 配置 (TUIC 原生字段名)
│   ├── logging.rs          # JSON 结构化日志 → stdout
│   ├── metrics.rs          # 回环 HTTP 指标
│   ├── transport/          # ★ 传输层 (quinn-proto 驱动 + SRT 壳 + 加密)
│   │   ├── mod.rs          #   驱动循环 (tokio select! 桥接)
│   │   ├── driver.rs       #   quinn-proto Endpoint/Connection 驱动
│   │   ├── srt_shell.rs    #   SRT 0x80 外壳编解码 (握手/数据头/ACK)
│   │   └── crypto.rs       #   双阶段 AES-128-CTR 包级加密
│   ├── tuic/               # ★ TUIC 协议层 (传输无关)
│   │   ├── mod.rs
│   │   ├── proto.rs        #   Command 编解码 (Auth/Connect/Packet/Dissociate/Heartbeat)
│   │   ├── addr.rs         #   Address 编解码 (Domain/IPv4/IPv6)
│   │   └── udp.rs          #   UDP 分片重组 (FragmentReassemblyBuffer)
│   ├── client/             # 客户端
│   │   ├── mod.rs          #   连接管理 + 重连
│   │   ├── socks5.rs       #   SOCKS5 入口 (+HTTP 嗅探薄层)
│   │   └── proxy.rs        #   TCP/UDP 代理 → TUIC 命令
│   └── server/             # 服务端
│       ├── mod.rs          #   监听 + 连接管理
│       ├── auth.rs         #   TUIC 认证 (UUID+TLS exporter)
│       └── forward.rs      #   TCP/UDP 转发出口
├── configs/
├── Dockerfile
└── .github/workflows/
```

---

## 五、开发里程碑

### P0 · 传输层（回环验收）
- [ ] quinn-proto 驱动循环（tokio select! 桥接）
- [ ] SRT 0x80 外壳编解码（握手/数据头/ACK）
- [ ] 双阶段 AES-128-CTR 包级加密
- [ ] 回环验收：QUIC 连接建立 + 数据传输

### P1 · TUIC 协议层 + 客户端
- [ ] TUIC Command 编解码（5 种命令）
- [ ] Address 编解码（Domain/IPv4/IPv6）
- [ ] UDP 分片重组
- [ ] 客户端 SOCKS5 + HTTP 代理薄层
- [ ] TCP/UDP 代理 → TUIC 命令

### P2 · 服务端 + 端到端
- [ ] 服务端监听 + 连接管理
- [ ] TUIC 认证（UUID+TLS exporter）
- [ ] TCP/UDP 转发出口
- [ ] 端到端回环测试

### P3 · 部署与 passwall
- [ ] Docker/CI 适配
- [ ] passwall 插件适配
- [ ] 公网验证 + SRT 特征抓包

---

*本文档随重构推进持续更新。*
