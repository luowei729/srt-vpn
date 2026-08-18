# SRT-VPN

基于 **SRT 直播流协议** 的 VPN 隧道（伪装为 SRT 直播流量，原生加密 + 多路复用）。

- **服务端**：监听 SRT UDP 端口，认证后为多个客户端提供直连转发出口
- **客户端**：SOCKS5 + HTTP + HTTPS 三合一代理入口，经加密隧道到服务器
- **协议**：单 SRT 连接 + 多路复用层（会话复用），可靠传输交给 SRT 层

---

## 一、启动命令

### 服务端（Server）
```bash
# 原生
./target/release/srt-vpn -c configs/server.conf

# Docker（Alpine 镜像，--net=host 暴露 SRT UDP）
docker run -d --name srt-vpn-server --restart=unless-stopped \
  --network=host \
  -v /opt/srt-vpn/server.conf:/app/configs/server.conf:ro \
  ghcr.io/<你的用户名>/<仓库名>:latest -c /app/configs/server.conf
```

### 客户端（Client）
```bash
# 原生
./target/release/srt-vpn -c configs/client.json

# Docker（映射 SOCKS5 TCP 端口，SRT 走宿主机网络）
docker run -d --name srt-vpn-client --restart=unless-stopped \
  --network=host \
  -v /opt/srt-vpn/client.json:/app/configs/client.json:ro \
  ghcr.io/<你的用户名>/<仓库名>:latest -c /app/configs/client.json
```

### CLI 参数
```
-c, --config <FILE>       配置文件路径（server.conf / client.json，JSON）
-m, --udp-mode <MODE>     服务端 UDP 模式：reliable | best-effort（覆盖配置）
-v, --verbose <LEVEL>     日志级别 0-4（默认 2）
    --socks5-listen <A>   客户端 SOCKS5 监听（覆盖配置）
    --socks5-user <U>     客户端 SOCKS5 用户名（覆盖配置）
    --socks5-pass <P>     客户端 SOCKS5 密码（覆盖配置）
-h, --help                帮助
```

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
