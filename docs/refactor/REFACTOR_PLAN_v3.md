# SRT-VPN 重构设计（Rust 自研 QUIC 语义内核 + 手写 SRT 全仿外壳）

> 版本：v0.3 设计（2026-08-20 北京时间）
> 状态：**设计完成，待 P0 实施**
> 前置：PROJECT_PLAN.md 的 grilling 盘问共识（见第五节"共识清单"）

---

## 一、背景与动机

### 1.1 为什么重构

现有 srt-vpn 用 **libsrt 1.5.6**（C++ 静态库 + Rust FFI）作为 SRT 传输承载。经过多轮带宽优化后发现**结构性天花板**：

- libsrt 的拥塞控制（FileCC / LiveCC）是 **单连接级全局单窗口 + 单发送时隙**（subsection：`core.h` CUDT 持有 `SrtCongestion m_CongCtl`；`core.cpp:10324` `packUniqueData` 用 `min(flowWindow, congWindow)` 守门）。
- 多线程/多路并发**共享同一拥塞窗口** → 公网高 RTT 下单连接是瓶颈（对照实验：单连接 89MB/s vs 4 连接并发 151MB/s）。
- libsrt 的拥塞窗口粒度固定在 CUDT（单物理连接），**无法从 API 拆出 per-stream 窗口**，改 C++ 拥控层又远超正常使用范围。

### 1.2 目标（来自盘问共识）

1. **真 QUIC 传输语义**（借鉴 RFC 9000）：帧机制、多流、丢包补发、拥塞控制（BBR 优先）——**学 QUIC 流控即可跑满带宽**
2. **手写 SRT 全仿外壳**：首包 `0x80 00 00 00` 握手 + 16B 固定头（SEQ/消息号/时间戳/ID）+ ACK 节奏——**流量特征伪装成 SRT 直播流**
3. **彻底废弃 libsrt**：移除 build.rs / FFI / C 依赖，纯 Rust
4. **不保留现有双 HMAC**：认证改为**学习 SRT 特征处理**（拟真 libsrt 握手加密特征），防主动探测
5. 前端功能（socks5/HTTP/UDP 代理）需求一致，保留现有分层接口

### 1.3 关键架构判断（为什么不用标准 QUIC 库）

标准 QUIC 库（quiche/msquic/s2n-quic/tquic）绑死 **TLS 1.3 Initial 明文**（首包 `0xC0` 长包头 + ClientHello 明文）——这是 QUIC 栈的不可去除指纹，DPI 一看就不是 SRT。**要全仿 SRT（首包 `0x80` + 无 TLS），必须自研"借鉴 QUIC 传输机制"的轻量内核**。

---

## 二、共识清单（盘问收束，2026-08-20）

| # | 决策点 | 结论 |
|---|--------|------|
| A | 核心形态 | Rust 全盘自研，不依赖 libsrt / quiche / msquic |
| B | 传输内核 | 真 QUIC 语义（帧/多流/丢包补发/拥塞控制），**首包按 SRT 0x80、无 TLS 明文** |
| C | 外壳 | 手写 SRT 壳：0x80 握手 + 16B 头（SEQ/消息号/时间戳/ID）+ ACK 节奏 |
| D | libsrt | **彻底废弃**（移除 build.rs 静态编译/FFI/C 依赖） |
| E | 认证 | 学习 SRT 特征处理（拟真 libsrt 握手加密特征），**不保留现有双 HMAC** |
| F | 流控 | 单连接共享拥塞窗口（学 QUIC 流控即跑满带宽） |
| G | 前端 | socks5/HTTP/UDP 代理功能一致，复用现有分层接口 |
| H | passwall | 重构后按新核心再适配（不锁定旧套壳） |

---

## 三、线协议设计草图

### 3.1 外层：SRT 全仿壳（每 UDP 数据报）

每个 UDP 负载是一个 **SRT 外形包**，结构与 libsrt 对齐以便 DPI 识别为 SRT/UDT：

```
┌───────────────────────────── 外层 SRT 壳（16B 固定）──────────────────────┐
│ 0-3   SEQNO:   bit31=0 数据 / =1 控制；bit30..16 = 消息类型；bit15..0 = 扩展 │
│ 4-7   MSGNO:   bit31-30 边界；bit29 顺序；bit28-27 key 标志；bit26 重传；    │
│                bit25-0 消息序号                                             │
│ 8-11  TIMESTAMP: 32 位微秒时间戳（TSBPD 用）                                │
│ 12-15 ID:        目标 socket ID                                             │
├───────────────────────────── 内层：传输帧 ─────────────────────────────────┤
│ 自研内核帧（见 3.2）                                                         │
└────────────────────────────────────────────────────────────────────────────┘
```

- 握手首包：控制包 + 类型=HANDSHAKE（bit31=1, 类型=0）→ 首 4 字节 `0x80 00 00 00`，后续跟随握手扩展字段
- ACK 包：控制包 + 类型=ACK（bit31=1, 类型=2）→ 首 4 字节 `0x80 02 00 00`，携带 ACK 序号等控制信息
- 数据包：`bit31=0`，即首字节 `0x00..0x7f`（视类型）

### 3.2 内层：传输帧（自研 QUIC 语义）

SRT 壳内封入传输帧（每包固定变帧布局，借鉴 RFC9000 的 varint / 帧类型）：

```
[帧类型 varint][流 ID varint][偏移 varint][长度 varint][数据]
[ACK 帧][STREAM 帧][PING][PONG][RST_STREAM][流控帧 MAX_STREAM_DATA / MAX_DATA]
```

- **STREAM 帧**：复用层多流（256 上限），每 TCP 会话映射一条流
- **ACK 帧**：确认已收序号 → 驱动拥塞控制窗口
- **拥塞控制**：BBR 风格（学 QUIC 流控），单连接共享一个拥塞窗口（决策 F）
- **丢包补发**：NACK/Timer-based 重传，等价 QUIC 的丢失恢复

### 3.3 握手与认证

- 握手按 SRT 外形（0x80 控制 + HANDSHAKE 类型 + 版本 + ReqType）——**拟真 libsrt 行为**
- 认证**学习 SRT 特征**：加密特征（密钥派生/kext消息模式）+ 握手握手模式，防主动探测（不保留现有双 HMAC 挑战）
- 后续同 hy2：认证通过后转为代理连接

### 3.4 TS 伪装层去留

- **TS 伪装层已因带宽优化删除**（AGENTS 2026-08-19 04:00：TS 壳只增 8 倍开销）
- 重构不再引入 TS；外壳就是 SRT 外形本身

---

## 四、目录结构（新架构）

```
srt-vpn/
├── Cargo.toml                # 移除 build.rs / libc 依赖；new name 保持 srt-vpn
├── src/
│   ├── main.rs               # 入口：CLI + 模式分发（不变）
│   ├── cli.rs                # CLI 解析（不变，-c / -v / -h）
│   ├── config.rs             # 配置加载（保留，精简字段）
│   ├── logging.rs            # JSON 日志（不变）
│   ├── metrics.rs            # 回环 HTTP 指标（不变）
│   ├── quic/                 # ★ 新：自研 QUIC 语义传输内核
│   │   ├── mod.rs            #   传输模块面
│   │   ├── packet.rs         #   包编码/解码（varint/帧）
│   │   ├── stream.rs         #   多流接口（256 流）
│   │   ├── ack.rs            #   ACK / 丢包恢复
│   │   ├── congctl.rs        #   拥塞控制（BBR 起始，CUBIC 可选）
│   │   ├── connection.rs     #   连接状态机（握手/运行/关闭）
│   │   └── crypto.rs         #   载荷加密（SRT 特征密钥派生）
│   ├── srt_shell/            # ★ 新：手写 SRT 全仿外壳
│   │   ├── mod.rs            #   外壳生成/解析
│   │   ├── header.rs         #   SRT 16B 头 + 首包 0x80
│   │   ├── handshake.rs      #   SRT 特征握手（拟真 lib11srt）
│   │   ├── ack.rs            #   ACK 节奏仿真
│   │   └── auth.rs           #   SRT 特征认证（非 double HMAC）
│   ├── tunnel/               # 复用层（收拾归并，改为调 quic 多流）
│   │   ├── mod.rs
│   │   └── multiplex.rs      #   会话路由（保留，改调 quic::stream）
│   ├── client/               # 客户端（保留前端接口，换内核）
│   │   ├── mod.rs
│   │   ├── socks5.rs
│   │   ├── proxy.rs
│   │   ├── http_proxy.rs
│   │   └── pool.rs           #   B 方案多连接池（保留，新内核每个连接独立拥控窗口）
│   ├── server/               # 服务器（保留前端接口，换内核）
│   │   ├── mod.rs
│   │   ├── listener.rs
│   │   └── forward.rs
│   └── auth/                 # 删（双 HMAC 移入 srt_shell/auth.rs）
├── build.rs                   # 移除（无 C 依赖了）—— 改 Cargo 直接编译
├── srt-1.5.6/                 # 保留源码备查，但不参与构建（README 注明）
├── docs/reference/            # 参考：RFC/中文/quiche/hysteria
└── docs/refactor/             # 本设计文档
```

### 移除

- `src/srt/`（libsrt FFI 封装）
- `src/auth/`（双 HMAC，合入 `srt_shell/auth.rs`）
- `build.rs` / `[build-dependencies] cc = "1"`（C 编译）
- `srt-1.5.6/` 不参与构建（源码备查）
- `src/tunnel/ts.rs`（无 TS）

---

## 五、里程碑任务清单

### P0 · 内核 + 外壳（回环验收）

- [ ] `quic/` 自研传输层：varint / 帧编码 / 多流 / ACK / 丢包恢复 / 拥塞控制 BBR
- [ ] `srt_shell/` 手写 SRT 壳：0x80 握手 + 16B 头 + ACK 节奏
- [ ] `srt_shell/auth.rs` SRT 特征认证（拟真握手/密钥）
- [ ] 移除 libsrt / build.rs / auth （清依赖）
- [ ] 回环吞吐验收：自研内核 vs 现有基线（39/61 MB/s）对比
- [ ] 回环丢包/补发模拟测试

### P1 · 前端功能重建

- [ ] socks5/HTTP/UDP 代理重接新内核（保留前端接口）
- [ ] 多流传输：每 TCP 会话一 QUIC 流（256 流）
- [ ] 认证/指标/日志保留（metrics/logging）
- [ ] 26 个现有单测迁移/重写为新内核
- [ ] 端到端回环：TCP/UDP(4类) 全验证

### P2 · 部署与 passwall

- [ ] passwall 按新内核适配（节点类型/二进制名/配置协商）
- [ ] Docker / CI（双架构 amd64/arm64）
- [ ] 公网多线程验证（学 QUIC 流控跑满带宽目标）
- [ ] 公网 SRT 外壳特征验证（用被动 DPI 方法抓包确认）

---

## 六、参考（docs/reference/）

- RFC 9000 / 9001 / 9002（QUIC 传输/TLS/恢复）
- quiche/（Cloudflare 实现——借鉴其帧布局与流控参考）
- hysteria/（hy2——借鉴其"QUIC 内核 + 外壳"架构思路）
- srt-1.5.6/（外壳特征字节来源，源码备查）

---

*本文档随重构推进持续更新。*