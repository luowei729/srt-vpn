# SRT-VPN

基于 **SRT 直播流协议** 的 VPN 隧道（伪装为 SRT 直播流量，原生加密 + 多路复用）。

> ⚠️ **重构中（PX，2026-08-20）**：传输内核正从 libsrt 重构为 Rust 自研 QUIC 语义内核 + 手写
> SRT 全仿外壳（详见 `docs/refactor/REFACTOR_PLAN_v3.md` 与 PROJECT_PLAN 第五节）。本文档为
> 当前可用版本（v0.2.x，libsrt 时代）的使用说明，重构落地后同步更新。

- **服务端**：监听 SRT UDP 端口，认证后为多个客户端提供直连转发出口
- **客户端**：SOCKS5 + HTTP + HTTPS 三合一代理入口，经加密隧道到服务器
- **UDP 代理**：SOCKS5 UDP ASSOCIATE 多目标 + 大包分片重组（支持至 65507B）
- **协议**：单 SRT 连接 + 多路复用层（会话复用），可靠传输交给 SRT 层

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
srt-1.5.6/       libsrt 官方源码（构建时静态编译，不动它）
src/
  srt/           libsrt FFI 封装（bindings + connection 事件循环）
  tunnel/        多路复用层（帧协议 + 会话路由）
  auth/          streamid 令牌 + 挑战-应答认证
  client/        SOCKS5 + HTTP/HTTPS 三合一代理入口
  server/        监听 + 认证 + 直连转发出口
  config.rs      JSON 配置（统一 schema）
configs/        示例配置
deploy/          systemd 单元
```

---

## 四、更多文档
- [DOCKER.md](./DOCKER.md) — Docker 容器化部署（构建/启动/配置映射）
- [AGENTS.md](./AGENTS.md) — 开发提示与约定
- [PROJECT_PLAN.md](./PROJECT_PLAN.md) — 架构设计
- [CHANGELOG.md](./CHANGELOG.md) — 变更日志
