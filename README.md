# SRT-VPN

基于 **SRT 直播流协议** 的 VPN 隧道：**libsrt 1.5.6 单连接多路复用（专注稳定高多线带宽，不叠 RTP）**
（2026-08-22 回归定版，v0.5.0，见 `docs/refactor/REFACTOR_PLAN_v5.md` 与 `CHANGELOG.md` 2026-08-22 22:40 条目；v0.4.x 自研 quinn-proto+TUIC+RTP 已归档）。

> 架构：`libsrt 1.5.6` 源码内嵌静态编译（`build.rs` CMake + `srt-1.5.6/`）+ 单 SRT 连接 `src/srt`（SRT FFI + 单发单收串行化 `mpsc→srt_sendmsg MJ_AGAIN 100μs 重试`）+ 多路复用 `src/tunnel`（变长帧 `ver|type|sid|len` + 轮询256K窗口+讣告）+ 三件套认证 `src/auth`（`passphrase+streamid+HMAC 90s` 对时握手）。单 UDP 流伪装最好，`S1/S5/S6` 三件套保稳定。已验：`16DL 93.2/16UL 55.6 双向同时 85.3 MB/s 32/32 无互踩`。

- **服务端**：监听 UDP 端口，`streamid` 令牌 + `HMAC` 挑战-应答对时握手（90s 窗，防重放）后为多客户端提供直连转发
- **客户端**：SOCKS5 + HTTP + HTTPS 三合一代理入口（首字节嗅探，同端口），经加密隧道到服务器
- **协议**：复用层 15B 帧头（`SRTV` Magic + `ver|type|sid|len|seq|flags`）+ UDP 分片重组（`0xFF` 标记）+ 三件套认证（`passphrase/streamid/HMAC`）
- **传输**：`SRTT_FILE` FileCC + 单发单收串行化（`crossbeam mpsc` → `srt_sendmsg inorder=1`，`MJ_AGAIN` 自旋重试）+ `epoll IN|ERR` 批量 `srt_recvmsg` → `tokio mpsc`，`SND32M/RCV11M≤FC65536/UDP4M/8M`，`rmem_max≥32M`
- **性能**：本机回环 `93.2 MB/s（16DL）/55.6 MB/s（16UL）/双向同时 85.3 MB/s 32/32 无互踩`（10M/100M MD5 一致，`4×100M DL 92.7/UL 70.3 双向 83.2` 全过，30 单测零告警，`release 5.0M`）

---

## 一、启动命令

### 服务端（Server）
```bash
# 原生（配置文件方式）
./target/release/srt-vpn -c configs/server.conf

# 原生（纯环境变量方式，无需配置文件）
SRT_MODE=server SRT_PASSPHRASE=你的强密码 SRT_LISTEN=0.0.0.0:9000 ./target/release/srt-vpn

# Docker（--net=host 暴露 SRT UDP；-e 环境变量指定参数，无需挂载配置文件）
# 日志限制：--log-opt max-size=10m max-file=3 防止 json-file 日志无限增长（详见 DOCKER.md 六、日志管理）
docker run -d --name srt-vpn-server --restart=unless-stopped \
  --network=host \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  -e SRT_MODE=server \
  -e SRT_PASSPHRASE=你的强密码 \
  -e SRT_LISTEN=0.0.0.0:9000 \
  ghcr.io/luowei729/srt-vpn:latest
```

### 客户端（Client）
```bash
# 原生（配置文件方式）
./target/release/srt-vpn -c configs/client.json

# 原生（纯环境变量方式，可完整指定 SOCKS5 监听 IP/端口/用户名/密码）
SRT_MODE=client SRT_PASSPHRASE=你的强密码 SRT_SERVER=服务器IP:9000 \
  SRT_SOCKS5_LISTEN=0.0.0.0:1080 SRT_SOCKS5_USER=user1 SRT_SOCKS5_PASS=password123 \
  ./target/release/srt-vpn

# Docker（映射 SOCKS5 端口；-e 环境变量指定参数）
# 日志限制：--log-opt max-size=10m max-file=3 防止 json-file 日志无限增长（详见 DOCKER.md 六、日志管理）
docker run -d --name srt-vpn-client --restart=unless-stopped \
  -p 1080:1080 \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  -e SRT_MODE=client \
  -e SRT_PASSPHRASE=你的强密码 \
  -e SRT_SERVER=服务器IP:9000 \
  -e SRT_SOCKS5_LISTEN=0.0.0.0:1080 \
  -e SRT_SOCKS5_USER=user1 \
  -e SRT_SOCKS5_PASS=password123 \
  ghcr.io/luowei729/srt-vpn:latest
```

### CLI 参数
```
-c, --config <FILE>       配置文件路径（可选；省略时用 SRT_* 环境变量配置）
-v, --verbose <LEVEL>     日志级别 0-4（默认 2，可用 SRT_LOG_LEVEL 覆盖）
    --socks5-listen <A>   客户端 SOCKS5 监听（覆盖配置/环境变量）
    --socks5-user <U>     客户端 SOCKS5 用户名（覆盖）
    --socks5-pass <P>     客户端 SOCKS5 密码（覆盖）
-h, --help                帮助
```

### 环境变量（`-e` 指定，覆盖配置文件；所有配置参数均可覆盖）

| 环境变量 | 对应配置字段 | 角色 |
|---|---|---|
| `SRT_MODE` | `mode` | 通用（必填） |
| `SRT_PASSPHRASE` | `passphrase` | 通用（必填） |
| `SRT_CRYPTO` | `crypto` | 通用 |
| `SRT_METRICS_PORT` | `metrics_port` | 通用 |
| `SRT_LOG_LEVEL` | `log_level` | 通用 |
| `SRT_LISTEN` | `listen` | server（必填） |
| `SRT_UDP_MODE` | `udp_mode` | server |
| `SRT_MAX_CLIENTS` | `max_clients` | server |
| `SRT_SOCKS5_USERS` | `socks5.users` | client（`user:pass,user2:pass2`，多用户表，argon2 存储，优先于单用户） |
| `SRT_SERVER` | `server` | client（必填） |
| `SRT_STREAMID` | `streamid` | client |
| `SRT_SOCKS5_LISTEN` | `socks5.listen` | client（监听 IP+端口） |
| `SRT_SOCKS5_USER` | `socks5.username` | client |
| `SRT_SOCKS5_PASS` | `socks5.password` | client |
| `SRT_RECONNECT_INTERVAL` | `reconnect.interval_secs` | client |
| `SRT_RECONNECT_MAX` | `reconnect.max_retries` | client |
| `SRT_HEARTBEAT_SECS` | `heartbeat_secs` | client |

> 配置优先级：CLI > 环境变量(SRT_*) > 配置文件 > 默认值
> `-m` 已移除（2026-08-20）：UDP 模式直接用 `SRT_UDP_MODE` 或配置文件 `udp_mode` 指定
> Docker 场景无需挂载配置文件，全部用 `-e SRT_*` 指定；也支持配置文件 + `-e` 覆盖混合方式

### 多用户语义与端口冲突说明（2026-08-19 补充）

**streamid 默认值不会冲突**：streamid 在本项目里不是用户标识，而是 passphrase 派生令牌的载体
（`k=HMAC-SHA256(passphrase,固定盐)`，伪装部分 `r=live/srtvpn,m=video` 服务端不解析）。
多用户共用默认 streamid = 共用同一 passphrase，认证全通过，属设计使然（单 passphrase 单信任域）。
服务端 accept 后每客户端独立 SessionRegistry（决策 Q20），会话空间互不干扰。

**当前“多用户”的真实语义**：

| 层 | 认证什么 | 区分用户吗 |
|---|---|---|
| SRT passphrase + streamid 令牌 | 有无共享密钥（服务端单租户） | ❌ 日志只有 IP，无法审计/踢人 |
| 挑战-应答（双 HMAC） | 同上（防重放加固） | ❌ 同上 |
| SOCKS5 用户表（单用户或多用户表） | 谁能用本机 SOCKS5 入口（客户端本地认证） | ✅ 仅客户端入口，与服务端无关 |

**同机多客户端进程时的真实冲突点**（唯一需要注意的场景）：

| 参数 | 默认值 | 冲突 |
|---|---|---|
| `socks5.listen` | `127.0.0.1:1080` | **必冲突**（端口占用，进程会报 `listen:` 错误优雅退出，需每进程显式配不同端口） |
| `metrics_port` | 关闭 | 仅配了相同端口才冲突，错开或不开 |
| streamid / server / heartbeat / reconnect 等 | - | 不冲突（进程间完全独立） |

> 服务端参数（listen/passphrase/crypto/udp_mode/max_clients）是单进程全局的，
> 所有客户端必须与其一致，不存在各配各的。
> 如需服务端级真多用户（每人独立凭证/审计/踢人），属 P2 协议扩展：
> streamid 增加 `u=<username>` 字段 + per-user 密钥表 + 每用户连接数上限。

---

## 二、配置映射（server.conf / client.json 统一 JSON schema）

### 必填项（启动必须指定，否则报错）
| 字段 | 角色 | 说明 |
|---|---|---|
| `mode` | 通用 | `"server"` 或 `"client"` |
| `passphrase` | 通用 | 10-79 字符，SRT 加密密钥，**两端必须一致** |
| `listen` | server | 监听地址，如 `"0.0.0.0:9000"` |
| `server` | client | **服务器 IP:端口**（如 `"129.150.44.117:9000"`），必须指定 |

### 可选默认项（省略即用默认）
| 字段 | 角色 | 默认值 |
|---|---|---|
| `crypto` | 通用 | `aes-128` |
| `metrics_port` | 通用 | 关闭（回环指标 HTTP） |
| `udp_mode` | server | `reliable` |
| `max_clients` | server | `32` |
| `socks5_users` | server | `[]`（客户端 SOCKS5 认证用户表） |
| `streamid` | client | 内置格式（自动附 k= 令牌） |
| `socks5.listen` | client | `127.0.0.1:1080` |
| `socks5.username/password` | client | 无认证 |
| `reconnect.interval_secs` | client | `5` |
| `reconnect.max_retries` | client | `10` |
| `heartbeat_secs` | client | `5` |

### 配置示例

**configs/server.conf**
```json
{
  "mode": "server",
  "listen": "0.0.0.0:9000",
  "passphrase": "change-me-strong-passphrase-2026",
  "udp_mode": "reliable",
  "max_clients": 32,
  "metrics_port": 9090,
  "socks5_users": []
}
```

**configs/client.json**
```json
{
  "mode": "client",
  "server": "127.0.0.1:9000",
  "passphrase": "change-me-strong-passphrase-2026",
  "streamid": "#!::r=live/srtvpn,m=video",
  "socks5": { "listen": "0.0.0.0:1080" },
  "reconnect": { "interval_secs": 5, "max_retries": 10 },
  "heartbeat_secs": 5,
  "metrics_port": 9091
}
```

---

## 三、项目结构
```
srt-1.5.6/       libsrt 1.5.6 官方源码（`build.rs` CMake 静态编译，不动源码树）
src/
  srt/           libsrt FFI 封装（bindings.rs / connection.rs 单发单收 + FileCC 16M）
  tunnel/        多路复用层（multiplex.rs 15B 帧头 + dispatch.rs 会话事件型 + 讣告）
  auth/          三件套认证（challenge.rs 对时握手 90s 窗 + mod.rs argon2）
  client/        SOCKS5 + HTTP/HTTPS 三合一代理入口（socks5.rs + proxy.rs + http_proxy.rs + mod.rs）
  server/        监听 + 认证 + 转发（mod.rs + listener.rs 常驻 + forward.rs TCP/UDP 双栈）
  cli.rs / config.rs / logging.rs / main.rs / metrics.rs
configs/        示例配置（server.conf / client.json，`fc426c4` 生产模板）
deploy/          systemd 单元
docs/refactor/   重构设计（REFACTOR_PLAN_v5.md 15题共识，Q15 双工）
```

---

## 四、更多文档
- [DOCKER.md](./DOCKER.md) — Docker 容器化部署（构建/启动/配置映射）
- [AGENTS.md](./AGENTS.md) — 开发提示与约定
- [PROJECT_PLAN.md](./PROJECT_PLAN.md) — 架构设计
- [CHANGELOG.md](./CHANGELOG.md) — 变更日志
