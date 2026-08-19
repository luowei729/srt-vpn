# SRT-VPN Docker 容器化部署

## 一、构建镜像（GitHub Actions 手动发布）

### 1. 推送代码到 GitHub 仓库
```bash
git remote add origin https://github.com/luowei729/srt-vpn.git
git push -u origin main
```

### 2. 手动触发编译发布
GitHub 仓库 → **Actions** 页 → `Build & Publish Docker Image` → **Run workflow**
（可填版本号，如 `1.0.0`；留空自动用 git describe）。

工作流自动（双 runner 并行原生编译，~2.5 分钟）：
- **amd64**：ubuntu-latest（x86_64 原生）
- **arm64**：ubuntu-24.04-arm（GitHub 原生 ARM runner，免 QEMU 模拟）
- 合并多架构 manifest → 推送 GHCR，打 `版本号` + `latest` 两个 tag

### 3. 本地构建（调试用）
```bash
docker build -t srt-vpn:local .
```

### 4. 拉取镜像
```bash
# 首次需登录
echo $GITHUB_TOKEN | docker login ghcr.io -u luowei729 --password-stdin
docker pull ghcr.io/luowei729/srt-vpn:latest
```

---

## 二、服务端（Server）启动

### 方式 1：Docker + 环境变量（推荐，无需配置文件）
```bash
docker run -d --name srt-vpn-server \
  --restart=unless-stopped \
  --network=host \
  -e SRT_MODE=server \
  -e SRT_PASSPHRASE=改成你的强密码 \
  -e SRT_LISTEN=0.0.0.0:9000 \
  ghcr.io/luowei729/srt-vpn:latest
```

### 方式 2：Docker + 配置文件 + 环境变量覆盖（混合）
```bash
# 基础参数在文件，需要临时改的用 -e 覆盖（无需重写配置）
docker run -d --name srt-vpn-server \
  --restart=unless-stopped \
  --network=host \
  -v /opt/srt-vpn/server.conf:/app/configs/server.conf:ro \
  -e SRT_PASSPHRASE=临时改的密码 \
  -e SRT_LISTEN=0.0.0.0:9100 \
  ghcr.io/luowei729/srt-vpn:latest \
  -c /app/configs/server.conf
```

### 方式 3：原生启动（非容器）
```bash
SRT_MODE=server SRT_PASSPHRASE=你的强密码 SRT_LISTEN=0.0.0.0:9000 \
  ./target/release/srt-vpn
# 或配置文件方式：./target/release/srt-vpn -c configs/server.conf
```

---

## 三、客户端（Client）启动

### 方式 1：Docker + 环境变量（推荐，可完整指定 SOCKS5 监听 IP/端口/用户名/密码）
```bash
docker run -d --name srt-vpn-client \
  --restart=unless-stopped \
  -p 1080:1080 \
  -e SRT_MODE=client \
  -e SRT_PASSPHRASE=与服务器相同的密码 \
  -e SRT_SERVER=你的服务器IP:9000 \
  -e SRT_SOCKS5_LISTEN=0.0.0.0:1080 \
  -e SRT_SOCKS5_USER=user1 \
  -e SRT_SOCKS5_PASS=password123 \
  ghcr.io/luowei729/srt-vpn:latest
```

### 方式 2：Docker + 配置文件 + 环境变量覆盖（混合）
```bash
docker run -d --name srt-vpn-client \
  --restart=unless-stopped \
  -p 1080:1080 \
  -v /opt/srt-vpn/client.json:/app/configs/client.json:ro \
  -e SRT_SERVER=新服务器IP:9000 \
  -e SRT_SOCKS5_LISTEN=0.0.0.0:1080 \
  ghcr.io/luowei729/srt-vpn:latest \
  -c /app/configs/client.json
```

### 方式 3：原生启动（非容器）
```bash
SRT_MODE=client SRT_PASSPHRASE=你的强密码 SRT_SERVER=服务器IP:9000 \
  SRT_SOCKS5_LISTEN=0.0.0.0:1080 SRT_SOCKS5_USER=user1 SRT_SOCKS5_PASS=password123 \
  ./target/release/srt-vpn
# 或配置文件方式：./target/release/srt-vpn -c configs/client.json
```

---

## 四、环境变量配置映射（所有配置参数均可 -e 覆盖）

| 环境变量 | 对应配置字段 | 角色 | 默认值 |
|---|---|---|---|
| `SRT_MODE` | `mode` | 通用 ✅ 必填 | 无 |
| `SRT_PASSPHRASE` | `passphrase` | 通用 ✅ 必填 | 无 |
| `SRT_CRYPTO` | `crypto` | 通用 | `aes-128` |
| `SRT_METRICS_PORT` | `metrics_port` | 通用 | 关闭 |
| `SRT_LOG_LEVEL` | `log_level` | 通用 | `-v` 默认 2 |
| `SRT_LISTEN` | `listen` | server ✅ 必填 | 无 |
| `SRT_UDP_MODE` | `udp_mode` | server | `reliable` |
| `SRT_MAX_CLIENTS` | `max_clients` | server | `32` |
| `SRT_SOCKS5_USERS` | `socks5_users` | server | `[]`（格式 `user:pass,user2:pass2`） |
| `SRT_SERVER` | `server` | client ✅ 必填 | 无 |
| `SRT_STREAMID` | `streamid` | client | 内置（自动附 k= 令牌） |
| `SRT_SOCKS5_LISTEN` | `socks5.listen` | client | `127.0.0.1:1080` |
| `SRT_SOCKS5_USER` | `socks5.username` | client | 无认证 |
| `SRT_SOCKS5_PASS` | `socks5.password` | client | 无认证 |
| `SRT_RECONNECT_INTERVAL` | `reconnect.interval_secs` | client | `5` |
| `SRT_RECONNECT_MAX` | `reconnect.max_retries` | client | `10` |
| `SRT_HEARTBEAT_SECS` | `heartbeat_secs` | client | `5` |

**配置优先级**：CLI > 环境变量(SRT_*) > 配置文件 > 默认值

**注意**：
- `-m` 已移除（2026-08-20）：UDP 模式用 `SRT_UDP_MODE` 或配置文件 `udp_mode` 指定
- Docker 场景**无需挂载配置文件**，全部用 `-e SRT_*` 指定
- 服务端 UDP（SRT）需 `--network=host`；客户端 SOCKS5 TCP 可 `-p 1080:1080`

---

## 五、镜像内路径约定

| 路径 | 用途 |
|---|---|
| `/usr/local/bin/srt-vpn` | 二进制 |
| `/app/configs/` | 配置文件挂载目录（可选，环境变量方式无需使用） |
| `/app` | 工作目录（srtvpn 用户，uid 1000） |

容器默认 `USER srtvpn`（非 root），若挂载配置文件需确保权限可读。
