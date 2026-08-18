# SRT-VPN Docker 容器化部署

## 一、构建镜像（GitHub Actions 手动发布）

### 1. 推送代码到 GitHub 仓库
```bash
git remote add origin https://github.com/<你的用户名>/<仓库名>.git
git push -u origin main
```

### 2. 手动触发编译发布
GitHub 仓库 → **Actions** 页 → `Build & Publish Docker Image` → **Run workflow**
（可填版本号，如 `1.0.0`；留空自动用 git describe）。

工作流自动：
- 构建 **amd64 + arm64** 双架构镜像
- 推送至 GHCR（GitHub Container Registry）
- 打 `版本号` + `latest` 两个 tag

> **注意（首次构建如失败）**：镜像基于 **Alpine (musl)**。若 GitHub Actions 构建日志
> 显示 libsrt C++ 编译报错（musl 兼容问题），可在 `Dockerfile` 将两阶段基础镜像
> 换回 Debian 系（`rust:1.97-slim` + `debian:bookworm-slim`），依赖包随之改为
> `libssl-dev` + `libstdc++6 libssl3`（glibc），其余不变。两种方案代码通用。

### 3. 本地构建（调试用）
```bash
# 需 Docker + 本机有 rust 重编（也可以直接 docker build）
docker build -t srt-vpn:local .
```

### 4. 拉取镜像
```bash
# 需先登录（首次）
echo $GITHUB_TOKEN | docker login ghcr.io -u <用户名> --password-stdin
docker pull ghcr.io/<你的用户名>/<仓库名>:latest
```

---

## 二、服务端（Server）启动

### 配置文件（server.conf）
```json
{
  "mode": "server",
  "listen": "0.0.0.0:9000",
  "passphrase": "改成你的强密码",
  "crypto": "aes-128",
  "udp_mode": "reliable",
  "max_clients": 32,
  "metrics_port": 9090,
  "socks5_users": []
}
```

### Docker 启动命令（宿主机映射）
```bash
# 服务端是 UDP（SRT），需 --network=host 暴露 UDP 端口；metrics 走回环
docker run -d --name srt-vpn-server \
  --restart=unless-stopped \
  --network=host \
  -v /opt/srt-vpn/server.conf:/app/configs/server.conf:ro \
  ghcr.io/<你的用户名>/<仓库名>:latest \
  -c /app/configs/server.conf
```

### 原生启动命令（非容器）
```bash
./target/release/srt-vpn -c configs/server.conf
# 可选参数：
#   -m reliable|best-effort      # UDP 传输模式（覆盖配置）
#   -v 2                         # 日志级别 0-4
```

---

## 三、客户端（Client）启动

### 配置文件（client.json）
```json
{
  "mode": "client",
  "server": "你的服务器IP:9000",
  "passphrase": "与服务器相同",
  "crypto": "aes-128",
  "streamid": "#!::r=live/srtvpn,m=video",
  "socks5": {
    "listen": "0.0.0.0:1080"
  },
  "reconnect": { "interval_secs": 5, "max_retries": 10 },
  "heartbeat_secs": 5,
  "metrics_port": 9091
}
```

### Docker 启动命令（宿主机映射）
```bash
# 客户端是 TCP SOCKS5 服务，映射 1080；SRT 走宿主机网络连服务器
docker run -d --name srt-vpn-client \
  --restart=unless-stopped \
  --network=host \
  -v /opt/srt-vpn/client.json:/app/configs/client.json:ro \
  ghcr.io/<你的用户名>/<仓库名>:latest \
  -c /app/configs/client.json
```

### 原生启动命令（非容器）
```bash
./target/release/srt-vpn -c configs/client.json
# 可选参数（覆盖配置）：
#   --socks5-listen 0.0.0.0:1080   # SOCKS5 监听地址
#   --socks5-user user1            # SOCKS5 用户名
#   --socks5-pass pass123          # SOCKS5 密码
#   -v 2                           # 日志级别
```

---

## 四、配置映射说明（必填 / 默认）

| 字段 | 角色 | 是否必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `mode` | 通用 | ✅ 必填 | 无 | `server` / `client` |
| `passphrase` | 通用 | ✅ 必填 | 无 | SRT 加密密钥，两端必须一致 |
| `crypto` | 通用 | ⭕ 可选 | `aes-128` | `aes-128/192/256` |
| `metrics_port` | 通用 | ⭕ 可选 | 关闭 | 回环指标 HTTP 端口 |
| `listen` | server | ✅ 必填 | 无 | 如 `0.0.0.0:9000` |
| `udp_mode` | server | ⭕ 可选 | `reliable` | `reliable`/`best-effort` |
| `max_clients` | server | ⭕ 可选 | `32` | 最大客户端数 |
| `socks5_users` | server | ⭕ 可选 | `[]` | 客户端 SOCKS5 认证用户表 |
| `server` | client | ✅ 必填 | 无 | 服务器 IP:端口，**必须指定** |
| `streamid` | client | ⭕ 可选 | 内置 | SRT streamid（含 k= 令牌自动附加） |
| `socks5.listen` | client | ⭕ 可选 | `127.0.0.1:1080` | SOCKS5 监听地址 |
| `socks5.username/password` | client | ⭕ 可选 | 无认证 | 本地 SOCKS5 认证 |
| `reconnect` | client | ⭕ 可选 | 5s/10次 | 自动重连 |
| `heartbeat_secs` | client | ⭕ 可选 | `5` | 心跳间隔 |

**规则**：只有 `mode`、`passphrase`、`server`（client）/`listen`（server）为必填；
其余字段可省略（省略即用默认值）。

---

## 五、镜像内路径约定

| 路径 | 用途 |
|---|---|
| `/usr/local/bin/srt-vpn` | 二进制 |
| `/app/configs/` | 推荐配置挂载目录（内置为空） |
| `/app` | 工作目录（srtvpn 用户，uid 1000） |

容器默认 `USER srtvpn`（非 root），挂载配置需确保权限可读。
