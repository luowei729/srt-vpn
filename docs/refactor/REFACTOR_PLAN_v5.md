# SRT-VPN 重构设计 v5（回归 libsrt 1.5.6 + 单连接多路复用）

> 版本：v0.5.0 设计（2026-08-22 北京时间）
> 状态：**共识确认，开始实施（推翻自研，回归 libsrt）**
> 前置：v0.4.8 自研 quinn-proto + TUIC + RTP/RTCP 外壳已验证 nDPI 达标，但用户判定“多轮修复无法根治”、要求彻底回归 libsrt
> 重要提醒：SRT 为单向推送优化，回包（反向）优化程度未知，验收必须双向同时压测（用户 2026-08-22 提醒，Q15）

---

## 一、背景与动机

### 1.1 为什么推翻自研

- v0.3.x → v0.4.8：自研 QUIC 语义内核 + 手写 SRT/RTP 外壳，历经 BBR→CUBIC、丢包恢复、连接池、RTCP 注入等多轮修复，本地 nDPI 验证 RTP 达标，但：
  - 自研传输层缺乏生产级成熟度，边界与竞态难收敛
  - 用户明确要求“推翻现有自研思路，已经多轮修复无法根治，重构项目还是基于 srt 核心去修改 srt 流量外壳”
  - 第一版 libsrt 方案曾验证单线正常但“多线上传卡死”，该坑需在新设计中正面规避，而非继续在自研上叠补丁

### 1.2 新方案一句话

**回归 libsrt 1.5.6 为唯一传输核心（源码内嵌静态编译），单 SRT 连接 + 应用层多路复用（256 会话）+ 变长帧 + 单发单收串行化，专注稳定高多线带宽，不再叠 RTP 伪装。**

- 伪装：原生 libsrt 流本身即 SRT，DPI 已识别为 SRT，无需再套 RTP
- 带宽：规避“多线程并发抢 srt_sendmsg / 共享 SNDBUF 拥控窗口”导致的卡死
- 认证：沿用第一版三件套（passphrase + streamid + HMAC 挑战，90s 窗）

---

## 二、共识清单（grilling 15 题，2026-08-22）

| # | 决策点 | 结论 | 备注 |
|---|--------|------|------|
| Q1 | 重构总方向 | **A 是，彻底推翻自研，回归 libsrt** | 删 src/transport src/tuic/quic，保留代理薄层 |
| Q2 | libsrt 集成 | **A 源码内嵌静态编译（srt-1.5.6/）** | build.rs CMake 静态库，最可控 |
| Q3 | 流量伪装策略 | **A 原生 libsrt 流即视为 SRT，不额外 RTP** | 专注带宽，DPI 已是 SRT |
| Q4 | 连接与并发模型 | **A 单 SRT 连接 + 应用层多路复用 256 会话** | 单 UDP 流伪装最好，关键是串行化 send |
| Q5 | 删除范围 | **A 全删：src/transport src/tuic 及相关 build** | 仅保留 client薄层/server框架/config |
| Q6 | libsrt 参数 | **A SRTT_FILE + TSBPD=0 + SND16M/RCV16M + UDP4M/8M** | FileCC 文件模式，VPN 突发最稳 |
| Q7 | 复用帧格式 | **A 变长帧 [ver1B|type1B|sid2B|len2B]+payload ≤1316** | v0.4.5 已证变长最优，无固定包放大 |
| Q8 | 收发线程模型 | **A 单发单收线程 + mpsc 串行化 srt_sendmsg** | 遇 SRT_EASYNCSND 则 epoll WRITE 等待，禁并发抢 |
| Q9 | 调度与流控 | **A 轮询 + 每会话 256K 窗口背压** | 推方决定流量，防僵尸会话占满 |
| Q10 | 消息模式 | **A inorder=1 强制有序** | 重传不超越，避免帧乱序错位 |
| Q11 | 认证方案 | **A 三件套：passphrase+streamid+HMAC（含90s）** | 复用第一版对时握手兼容 |
| Q12 | 额外伪装 | **A 不叠加，原生 SRT 足够** | 与 Q3 一致 |
| Q13 | 验收标准 | **A 16 线并发 100M 上传下载全 MD5 一致 + 单线程 50MB/s+** | 严格覆盖多线上传卡死场景 |
| Q14 | 交付节奏 | **A 分层：本地回环 → hk2 公网 16 线 → passwall** | 每层全绿再进下一层 |
| Q15 | 回包双工风险 | **A 验收加双向同时压测** | SRT 单向推送优化，回包未必同等；加“16下载+16上传同时跑”一项，互踩则再考虑双连接隔离 |

> Q15 特别说明（用户提醒）：
> - SRT 的 SndQueue/CongCtl/FlowWindow 围绕发送侧设计，虽有独立 RcvQueue/RcvBuffer，但拥控反馈以发送为中心
> - VPN 是全双工：下载（服务端→客户端）与上传（客户端→服务端）可能同时高吞吐
> - 若实测双向同时压测出现互踩（一方带宽被另一方压制），再考虑 B 方案：正反向各一条 SRT 连接隔离
> - 当前先保持单连接，通过变长帧与轮询调度保证公平，验收先暴露问题

---

## 三、线协议设计

### 3.1 传输：单 SRT 连接

- libsrt 参数（Q6）：
  - `SRTO_TRANSTYPE = SRTT_FILE`（FileCC，VPN 突发最稳；LiveCC 在突发下 behavior undefined）
  - `SRTO_TSBPDMODE = 0`（禁 TSBPD 延迟投递）
  - `SRTO_MESSAGEAPI = 1`（消息 API，保帧边界）
  - `SRTO_SNDBUF / SRTO_RCVBUF = 16 MB`，`SRTO_UDP_SNDBUF = 4 MB`，`SRTO_UDP_RCVBUF = 8 MB`
  - 注意：`SRTO_UDP_RCVBUF` 受内核 `net.core.rmem_max` 钳制（默认 208KB），部署需 `sysctl -w net.core.rmem_max=33554432`
  - `srt_sendmsg(..., inorder=1)`（Q10），`srt_recvmsg` 阻塞收（epoll IN 驱动）

### 3.2 复用：变长帧（Q7）

```
[ver:1B | type:1B | sid:2B BE | len:2B BE] + payload (≤1316B)

ver  = 0x01
type = 0x01 Open | 0x02 Data | 0x03 Fin | 0x04 Close | 0x05 Rst | 0x10 Heartbeat
sid  = 1..255（u16，256 上限，1 字节有效）
len  = payload 长度
```

- 约束：`len + 6 ≤ 1322`，低于 SRT 1316 典型载荷，避免分片
- UDP 大包分片在 proxy 层处理（沿用第一版 split_udp_frames，标记 0xFF）
- 无固定 1328/188 填充，变长直发（v0.4.5 定论）

### 3.3 调度与流控（Q9）

- 调度：轮询（round-robin）取各会话待发队列头部
- 背压：每会话 256 KB 窗口（`MAX_SESSION_WINDOW = 256*1024`），超窗则暂停该会话入队
- 讣告：任何会话退出路径必发 Close/Rst，对端收后立即停止该 sid 的流量（防僵尸会话白灌，见 2026-08-20 03:05 经验）

### 3.4 收发线程（Q8，规避多线卡死）

- 单发送线程：`mpsc::unbounded_channel<Vec<u8>>` 串行消费 → `srt_sendmsg` 阻塞发
  - 遇 `SRT_EASYNCSND`（MJ_AGAIN）→ `srt_epoll_wait(..., SRT_EPOLL_OUT, timeout)` 等待可写再重试，不丢包不退线程
  - 禁止多线程并发调 `srt_sendmsg` 抢 SNDBUF
- 单接收线程：`srt_epoll_wait(..., SRT_EPOLL_IN)` → `srt_recvmsg` → `dispatch_frame` 投递到对应 Session
- 关闭：`AtomicBool closed` CAS + `srt_close` + join 线程 + `srt_epoll_release` 归接收线程唯一释放（沿用 2026-08-19 15:00 三件套）

---

## 四、目录结构（新）

```
srt-vpn/
├── build.rs                  # ★ 恢复：CMake 编译 srt-1.5.6 静态库
├── Cargo.toml                # 精简：删 quinn-proto/quinn-udp/rustls/aes/ctr 等，加 cc/libc
├── src/
│   ├── main.rs               # 入口：CLI + 模式分发（保留）
│   ├── cli.rs                # -c/-V/-h（保留）
│   ├── config.rs             # JSON + SRT_* env（需改回 srt 字段：passphrase/listen/udp_mode 等）
│   ├── logging.rs            # JSON 日志（保留）
│   ├── metrics.rs            # 指标（保留）
│   ├── srt/                  # ★ 新：libsrt FFI 封装（替代 transport/tuic/quic）
│   │   ├── mod.rs
│   │   ├── bindings.rs       # srt.h 绑定（或最小手写）
│   │   └── connection.rs     # SrtConnection（单发单收 + epoll + 参设）
│   ├── tunnel/               # ★ 恢复：多路复用层（替代 tuic）
│   │   ├── mod.rs
│   │   ├── multiplex.rs      # 帧编解码（变长）
│   │   ├── session.rs        # SessionRegistry/TunnelSession（事件型）
│   │   └── dispatch.rs       # 分发与讣告
│   ├── auth/                 # ★ 恢复：三件套认证（passphrase/streamid/HMAC）
│   │   ├── mod.rs
│   │   └── challenge.rs      # HMAC + 对时握手（90s 窗）
│   ├── client/               # 薄层保留
│   │   ├── mod.rs            # 连接管理 + 重连（watch 信号）
│   │   ├── socks5.rs         # SOCKS5 入口（首字节嗅探三合一）
│   │   ├── http_proxy.rs     # HTTP 薄层（CONNECT + 普通 HTTP 改写）
│   │   └── proxy.rs          # 建隧道 + 转发（调 srt+ tunnel）
│   └── server/               # 保留
│       ├── mod.rs            # 监听 + 认证 + 会话管理
│       ├── listener.rs       # SrtListener（单 socket 串行 accept）
│       └── forward.rs        # 转发出站（TCP/UDP，含看门狗）
├── srt-1.5.6/                # 不动（官方源码）
├── configs/
├── Dockerfile                # 需改回 libsrt 构建依赖（cmake/openssl/linux-headers 等）
└── .github/workflows/
```

- 删除：`src/transport/**`、`src/tuic/**`、`src/quic/**`（若有）、旧 `src/srt`（若为 quinn 壳，清空重建）
- 保留：`src/client/socks5.rs` 三合一嗅探结构、`src/server/forward.rs` 看门狗、`src/config.rs` 框架（字段需回退 srt 语义）

---

## 五、开发里程碑（按 Q14 分层）

### P0 · 构建与封装（本地编译通过）

- [ ] 恢复 build.rs（CMake 静态库 + 链接 stdc++/crypto/ssl/pthread/m）
- [ ] 精简 Cargo.toml（删 quinn-proto/quinn-udp/rustls/aes/ctr/pbkdf2/uuid/bytes/quinn 依赖，加 cc/libc/argon2/hmac/sha2 等）
- [ ] 新建 src/srt/（SrtConnection：SRTT_FILE/TSBPD0/16M/单发单收/epoll）
- [ ] 恢复 src/tunnel/ + src/auth/（变长帧 + 三件套）

### P1 · 前端重接（回环打通）

- [ ] client/server 重接 srt+tunnel（SOCKS5 三合一 + forward 看门狗 + 心跳 5s + 重连）
- [ ] 本地回环：SOCKS5/HTTP 10M/100M 下载/上传 MD5 一致，单线程 ≥50MB/s

### P2 · 多线与双工验收（本地 16 线）

- [ ] 16 线并发 100M 上传/下载各 16 线全 MD5 一致
- [ ] **双向同时压测**：16 下载 + 16 上传同时跑，互不踩带宽（Q15）
- [ ] 若互踩，评估双连接隔离（B 方案）再决策

### P3 · 公网与 passwall

- [ ] hk2 公网 16 线验证（103.244.89.78，RTT 40ms 级）
- [ ] 抓包验证 SRT 特征（首字节、握手、流）
- [ ] openwrt-passwall-srt-vpn 适配（util_srt-vpn.lua / com.lua / app.sh）

---

## 六、风险与规避（来自第一版血泪）

- **多线上传卡死**：单发线程串行化是铁律；禁每会话线程直调 srt_sendmsg；SNDBUF/RCVBUF 足够大但受 rmem_max 钳制必调内核
- **半关闭与讣告**：Fin/Close 投事件不删会话，转发任务收事件后 shutdown 写侧；任何退出路径必发 Close/Rst
- **重连感知**：recv_loop 退出置 watch，socks5 serve select 信号退出，重连接管
- **inorder=1**：重传不超越，避免帧乱序错位
- **关闭与退出**：srt_global_init Once + atexit srt_cleanup + close 保存 join Handle + main 手工 runtime（防 CRcvQueue::worker 段错误）
- **端口与白名单**：原生 SRT 端口不限 DPI，无需 RTP 端口白名单；若后续为爱快再套 RTP，另议

---

*本文档随重构推进持续更新。最后更新：2026-08-22 北京时间（Q15 双工提醒纳入）。*
