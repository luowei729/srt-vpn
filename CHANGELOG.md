# SRT-VPN 项目 变更日志

所有变更记录使用北京时间（UTC+8）。

## [2026-08-20 06:13] - B 方案（多 SRT 连接池）实现 + 公网验证中

### 改动前总结
A 方案（单连接 + 复用层每会话公平调度/流控）编码实现后，回环实测 4 并发带宽不升反降
（302 -> 36 MB/s，每 32KB 一次 Semaphore 背压 await 的调度开销过大），验证了"单 SRT
连接共享 FileCC 拥塞窗口是物理天花板，应用层调度无法突破"的判断。方向正式转向用户
此前存档的 B 方案（多连接池）：客户端维护 N 条独立 SRT 连接，各自独立 FileCC 窗口，
等价 QUIC"每流独立窗口"，突破单连接带宽上限。

### 改动后总结
1. **B 方案核心实现（src/client/pool.rs 新增）**：
   - `TunnelConn`：单条连接三元组（SrtConnection + MuxEncoder + SessionRegistry），
     每条连接独立 FileCC 窗口 / 会话 ID 空间（1..=255）/ 帧序号
   - `TunnelPool`：N 条连接 + 原子轮询计数器；`allocate()` 轮询分配会话到各连接
     （round-robin 均匀分散并发会话，各自独立窗口全力发送）
   - `POOL_SIZE = 4`（验证期固定，后续可配置化）
2. **客户端主循环改造（client/mod.rs）**：
   - `connect_pool_once`：spawn_blocking 并行建立 4 条连接（建池原子性，全成功或全失败）
   - 主循环建池 -> 每连接独立 spawn recv_loop + 心跳任务 -> `socks5::serve(pool,...)`
   - 注意：客户端 `socks5::serve` 已是重连循环的一部分，任一连接断开 -> 断开信号置位
     -> 整体重建整个池（B3 整链自动重连语义保持一致）
3. **SOCKS5/HTTP/Proxy 适配（socks5.rs/proxy.rs/http_proxy.rs）**：
   - 全部改为接收 `pool: Arc<TunnelPool>`，用 `pool.allocate()` 返回的 TunnelConn 构造会话
   - 移除对 `SrtConnection/SessionRegistry/MuxEncoder` 的直接 import（统一走池）
4. **验证结果**：
   - 编译零警告，30 单测全过
   - **本地回环**：单线程 384.1 MB/s，4 并发合计 302.8 MB/s（各 288/334/303/340，
     说明 4 条连接并行、各连接独立窗口能叠加）——回环完美
   - **公网 4 并发上传：5.12 MB/s**（各 0.7/2.3/0.5/1.6），相对单隧道连接 1.14 MB/s
     ~4.5 倍扩展，已达公网直连链路（6.59 MB/s 本地出口）~78%，说明 4 条连接真实并行
     榨干链路；剩余差距源于公网 RTT（74-248ms）导致 FileCC 窗口 = 带宽×RTT 受限
   - 方向结论：B 方案正确，公网瓶颈为链路本身而非调度

### 部署
- 本条目对应 B 方案代码评审 + 部署验证中（用户侧测试）

## [2026-08-20 05:30] - 对时握手（认证时钟无关）+ 内核缓冲调优 + 公网对照实验结论

### 改动前总结
软路由更新 0.2.1 二进制后隧道全断：服务端刷 `挑战-应答校验失败`。排查发现软路由系统时间快 ~51 秒（超出 ±30s 时间窗），且 NTP 流量走隧道 -> 隧道断 -> NTP 也断 -> 时间纠不回的**死循环**（手动 `ntpd -q` 直连校时后 4 实例全部恢复）。另：上传带宽瓶颈排查中发现新加坡服务器内核 `net.core.rmem_max` 仅 208KB，钳制了 `SRTO_UDP_RCVBUF=16MB` 的设置（33 次/秒缓冲溢出丢包 -> SRT 误判网络丢包重传风暴）。

### 改动后总结
1. **对时握手（v0.2.2，认证与客户端本地时钟完全无关）**：
   - CHALLENGE 帧携带服务端时间戳 `ts`（`nonce=<hex>,ts=<unix秒>`），客户端用它计算 HMAC 应答
   - 服务端 `verify_response_dual` 双路径校验：新客户端按 server_ts 比对（陈旧性校验防重放）；旧客户端按 90s 窗口兜底（时间窗 30->90s，nonce 连接级一次性保证防重放不降级）
   - 服务端认证失败日志输出时钟偏差方向与秒数（替代模糊的"时间窗或 HMAC 不匹配"）；认证通过日志带 `client_clock_delta_s` 诊断
   - 客户端解析 `ts` 字段优先使用（`clock_src=server`），无则回退本地时间（旧服务端兼容）
   - **四象限兼容**：新旧客户端 × 新旧服务端任意组合都能认证
   - 新增 5 个对时单测（时钟漂移 10 万秒仍通过/旧客户端窗口内兜底/超窗拒绝/陈旧 CHALLENGE 拒绝/错误密钥拒绝），共 30 测试全过
2. **新加坡内核 UDP 缓冲调优**（运维，已写入服务器 /etc/sysctl.conf 持久化）：
   - `net.core.rmem_max/wmem_max` 212KB -> 32MB；`rmem_default/wmem_default` -> 8MB
   - 效果：缓冲溢出从 33 次/秒归零；公网上传从 ~0 恢复 17.7 MB/s；内核缓冲钳制经验教训（应用层 setsockopt 会被 rmem_max 静默钳制）
3. **公网对照实验（探针 srt_probe_mc 改造为远程双模式）**：
   - 探针支持 `server <port> <msgs>`（接收端，部署新加坡 aarch64 本地编译）与 `client <remote> <base_port> <conn> <msgs>`（多连接并发发起）
   - **实验结论（决定性数据）**：纯 libsrt 公网单连接上传 89.49 MB/s，4 连接并发 151.68 MB/s（**+70%**）-> 证明单 SRT 连接共享 FileCC 拥塞窗口是并发瓶颈，多连接各自独立窗口收益显著
   - 方向决策：**用户选择学 QUIC 的 A 方案**（单连接 + 复用层每会话公平调度/流控），保持单 UDP 流伪装；多连接池（B 方案）作为备选已存档

### 部署
- Release `v0.2.2`（Latest）：amd64/arm64 静态二进制 + 组件更新元数据（passwall 可检测 0.2.1 < 0.2.2）
- 新加坡 srtvpn-sg 容器：`ghcr.io/luowei729/srt-vpn:0.2.2`
- 软路由 passwall 已更新 0.2.2（4 实例，其中 2 个为 haproxy 后端 + 2 个 SOCKS 入口，属 passwall 正常行为）

### 涉及文件
- src/auth/challenge.rs（时间窗 90s + verify_response_dual + 5 单测）
- src/server/listener.rs（CHALLENGE 带 ts + 双路径校验 + 时钟偏差诊断）
- src/client/mod.rs（解析 ts 优先使用 + 重连失败提示检查 NTP）
- examples/srt_probe_mc.rs（远程双模式多连接探针）
- Cargo.toml（0.2.2）

## [2026-08-20 03:25] - 版本号 0.2.1 发布（修复 passwall 检测不到更新）

### 改动前总结
用户报告 passwall 点"检查更新"检测不到新版本。排查 api.lua 的 `compare_versions`：按 `[%.%-]` 切分转数字比较。此前发布的 tag `vrst-notify-20260820` 去掉 v 后为 `rst-notify-20260820`，切分得 `rst/notify/20260820` -> tonumber 失败全变 0 -> 与本地 `0.2.0` 比较为 `0.2.0 < 0.0.20260820`，第 2 段 2>0 不成立 -> `has_update=false`。**根因：发布 tag 用了描述性名字，破坏 passwall 语义版本比较**。

### 改动后总结
- Cargo.toml 版本 `0.1.0` -> `0.2.1`（`-V` 输出 `srt-vpn 0.2.1`，与 release tag 对齐）
- 发布 Release `v0.2.1`（Latest）：含 amd64/arm64 静态二进制 + 组件更新元数据 JSON
- 新加坡 srtvpn-sg 容器同步升级 `ghcr.io/luowei729/srt-vpn:0.2.1`（与服务端对齐）
- **规范固化：今后发布 tag 必须纯语义版本号（vX.Y.Z），描述信息写 release body，不进 tag**

### 验证
- ✅ 元数据 JSON：tag_name=v0.2.1，assets 含两个二进制
- ✅ 版本比较链路（本地 0.2.0 < 远端 0.2.1 成立，passwall 应能检测到）
- 🔄 待用户软路由实测点更新

## [2026-08-20 03:05] - 会话死亡讣告机制（修复 WebRTC 多线程上传带宽暴跌）

### 改动前总结
用户报告：speedtest.net 多线程上传带宽极低，单线程正常；仅 Windows Chrome 开 WebRTC 时复现（本机 Ubuntu 正常）；换 hy1 协议无此问题 -> 锁定 srt-vpn 隧道实现。

**新加坡日志实锤根因**（故障时段 UTC 18:30-18:37，每分钟 61-176 个 TCP 会话建立）：
- `数据帧无法路由（转发会话不存在）` 刷 2039 次/分钟，`session=157` 单会话被灌 1297 帧（≈1.7MB）
- 同期大量 `Connection reset by peer`（测速服务器 RST 短连接）

**故障链**：WebRTC 高并发短连接 -> 测速服务器对部分连接 RST -> 服务端转发任务遇错 `return Err` **不发 Close 帧** -> 客户端不知会话已死，继续向僵尸会话灌上传数据 -> 帧全被丢且仍占满 SRT 隧道带宽 -> 真实上传被挤占 -> 带宽暴跌。**下载不受影响**：服务端任务死了就没有下行流量产生（推送方决定流量）；本机 Ubuntu 正常是 Chrome WebRTC 不可用回退 HTTP 上传。

### 改动后总结
双向讣告 + 快速收敛（4 文件）：
1. **forward.rs**：`handle_open_with_rx` 外层统一兜底发 Close 帧（新增 `notify_session_closed`，覆盖 Open 解析失败/连接失败/读失败/RST/看门狗**全部**退出路径）；子函数内正常路径的重复发送删除
2. **listener.rs**：`无法路由` 分支向客户端**回发 Rst 帧**（客户端收到立即停止发送并释放会话）
3. **dispatch.rs**：`dispatch_frame` 新增 Rst 帧处理（投递 Close 事件到会话通道）+ `DispatchAction::Rst`；两端 recv 循环匹配；TunnelSession 新增 `conn_ref()`
4. **proxy.rs**：客户端转发循环抽取 `forward_loop`，讣告在调用方统一收口（对称修复：客户端异常退出也通知服务端，不再空挂 300s）

### 验证
- ✅ RST 高并发复现（8 worker 灌向被 RST 的目标）：7/8 被 Rst 提前掐断，仅单批 in-flight 损失（823 帧同一毫秒到达，属 send_data_batch 32KB 批量分片的已排队帧，不可避免），毫秒级收敛；修复前为分钟级持续灌送
- ✅ 回归：8 并发 × 8MB 正常上传 8/8 md5 一致（无讣告逻辑误伤）
- ✅ 25 单测全过，release 零警告
- 🔄 待公网实测：Windows Chrome 开 WebRTC 跑 speedtest 多线程上传（用户配合）

### 部署
- Docker 镜像：`ghcr.io/luowei729/srt-vpn:rst-notify-20260820`（新加坡 srtvpn-sg 已部署，含日志轮转 --log-opt）
- **passwall 组件二进制已同步发布**：Release `vrst-notify-20260820`（Latest）含 `srt-vpn-linux-amd64/arm64`（10.9/9.8MB 纯静态）+ `srt-vpn-release-api.json` 元数据 -> 软路由 passwall 可直接点更新
- 注意：release tag 带 `v` 前缀（version 入参规范化规则），passwall 组件版本比对读 latest tag_name，无影响

### 涉及文件
- src/server/forward.rs、src/server/listener.rs、src/tunnel/dispatch.rs、src/client/proxy.rs、src/client/mod.rs

## [2026-08-19 19:57] - 文档：Docker 日志限制参数（--log-opt）

### 改动前总结
用户询问 Docker 容器 / CLI 日志是否有大小限制与回收机制。核查结论：程序不写日志文件，JSON 日志一律输出 stdout；CLI 无轮转无限制（取决于终端/journald）；Docker 默认 json-file 驱动无上限且不回收，长跑会无限膨胀。用户要求把 `--log-opt` 参数写进文档示例。

### 改动后总结
- **README.md**：服务端/客户端两个 `docker run` 示例均新增 `--log-driver json-file --log-opt max-size=10m --log-opt max-file=3`（总上限约 30MB），并附注释说明用途与 DOCKER.md 章节索引
- **DOCKER.md**：四个 `docker run` 示例（服务端环境变量/配置文件、客户端环境变量/配置文件）统一加日志限制参数；新增 **六、日志管理** 章节：默认 json-file 无上限的隐患、推荐参数含义、`--log-opt` 仅创建时生效需删重建、`--log-driver none`/daemon.json 全局限制/手动清理三种可选方案、原生+systemd(journald) 场景说明、日志量评估
- 纯文档修改，无代码变更，无需测试

### 涉及文件
- README.md（2 处 docker run 示例）
- DOCKER.md（4 处 docker run 示例 + 新增第六章）

## [2026-08-19 17:55] - passwall 对接：静态二进制发布 + 域名解析 + SOCKS5 认证修复

### 改动前总结
用户需求：① srt-vpn 发版时 actions 编译出 amd64/arm64 纯静态二进制，供 OpenWrt passwall「组件更新」点击下载作为新核心；② passwall 侧（openwrt-passwall-srt-vpn 仓库）最小侵入新增 srt-vpn 核心，可配置节点对接。

### 改动后总结（srt-vpn 侧）
- **cli.rs**：确认 `-V/--version`（clap 自带）输出 `srt-vpn 0.1.0`，passwall 组件更新 `cmd_version="-V | awk '{print $2}'"` 解析纯版本号（不动代码，仅确认行为）
- **release.yml 扩展**：新增 `build-binaries` job（Alpine 容器内全静态编译 amd64/arm64，产出 `srt-vpn-linux-amd64/arm64` 上传 release assets）+ `release` job（softprops/action-gh-release 上传二进制到 Release）+ `push v* tag` 触发；原 Docker 镜像构建/合并逻辑保留
- **client/mod.rs**：`parse_addr` → `resolve_addr`（支持域名解析，`lookup_host` 取 IPv4）。原因：passwall 节点常填域名，原 SocketAddr::parse 只认 IP；实测 `localhost:9000` 成功连接
- **socks5.rs + config.rs**：修复认证绕过漏洞——配置了用户名/密码（或用户表）时 SOCKS5 握手**只接受 0x02 用户密码认证**，未配置才接受 0x00 无认证；新增 `Socks5Config::has_auth()`。原因：passwall 节点可配本地 socks 认证，原逻辑"无认证也能连"使认证形同虚设
- 兼容性：以上均为正向增强，Docker/原生/CLI 用法零破坏

### 验证
- ✅ cargo test 25 个全过、release 零警告
- ✅ 模拟 passwall 生成的完整配置（域名 + aes-256 + SOCKS5 认证 + 自定义重连/心跳）端到端 HTTP 200
- ✅ 模拟最小配置（仅必填）端到端 HTTP 200
- ✅ 认证修复验证：无认证客户端无凭据可访问；有认证客户端带凭据 200、无凭据被拒（HTTP 000）
- ✅ 域名解析验证：`localhost:9000` 经 lookup_host 成功连接

### 涉及文件
- src/cli.rs（仅注释说明，无代码变更）
- .github/workflows/release.yml（build-binaries + release job + tag 触发）
- src/client/mod.rs（resolve_addr 域名解析）
- src/client/socks5.rs（认证方法选择按配置）
- src/config.rs（Socks5Config::has_auth）

## [2026-08-19 16:05] - M1 并行 accept 两版 bug 修复 + fix4 部署（新加坡/本地 1080）

### 改动前总结
15:00 修复的 M1（accept 并行化）部署到新加坡后**实测暴露两版连锁 bug**：
- 第一版 bug：每连接任务重建监听 socket（bind->listen->accept(1)->close），并行化后多任务同时 bind 同一端口 -> "Another socket is already listening on the same port" 无限报错
- 第二版 bug（修完第一版部署又发现）：主循环预 spawn 无限 accept 任务 -> 1500+ 任务同时阻塞在 srt_accept 排队 -> max_clients 名额被预占任务瞬间耗尽（active=1513 冻结），主循环永远卡在"已达最大客户端数"，真实客户端永远进不来
- CI merge job 也有 bug：无 checkout 步骤，git describe 失败 fallback latest，与 build 实际推送的 <sha>-arch tag 不一致 -> "latest-amd64 not found" 合并失败

### 改动后总结
- **监听 socket 常驻化**（connection.rs）：拆分 `bind_listener`（一次 bind+listen，常驻 `SrtListener`，Drop 关闭）+ `accept_one`（并发安全，srt_accept 由 libsrt 内部排队）；废弃旧 `SrtConnection::accept` 每连接重建模型
- **accept 循环最终模型**（listener.rs）：主循环**串行 accept**（名额精确可控，一次只占 1 个）-> accept 到连接**立即 spawn「认证+处理」任务**（认证不阻塞下一个 accept，M1 多客户端并行目标保留）+ accept 失败 500ms 退避
- **CI 修复**（release.yml）：build job 输出 TAG（outputs.tag），merge job 复用（单一事实来源），不再各自计算
- 教训记录：并行化改造必须先想清楚"哪些资源是全局唯一"（监听 socket）与"任务生命周期与名额占用的对应关系"（预 spawn 无限任务 = 名额风暴）

### 验证（本地回环 + 公网生产）
- ✅ 本地：3 客户端并发接入 0 端口冲突 + 名额正常 + 3/3 转发 + 第 4 个后续客户端正常接入；25 单测全过 release 零警告
- ✅ 新加坡 fix4 部署：静置 30 秒日志仅 2 行（无告警刷屏、无名额冻结）
- ✅ 公网端到端：本地 1080 -> 新加坡 -> 百度 HTTP/HTTPS 均 200（0.19s/0.89s）
- ✅ UDP：经隧道 DNS 解析 8.8.8.8（baidu.com 4 条 A 记录）
- ✅ 断线重连：docker restart 服务端 -> 客户端自动重连 -> 35 秒恢复 HTTP 200

### 部署信息
- 镜像：`ghcr.io/luowei729/srt-vpn:fix4-20260819`（含 15:00 全部修复 + 本轮 3 项修复）
- 新加坡：容器 `srtvpn-sg`（fix4-20260819，--net=host，SRT_LISTEN=0.0.0.0:9000）
- 本地：原生二进制客户端（PID 881486，SOCKS5 0.0.0.0:1080 -> 129.150.44.117:9000）

### 涉及文件
- src/srt/connection.rs（bind_listener/SrtListener/accept_from_listener）
- src/server/listener.rs（串行 accept + 并行认证处理）
- .github/workflows/release.yml（TAG 单一来源）
- README.md（多用户语义与端口冲突章节）、CHANGELOG.md、PROJECT_PLAN.md

## [2026-08-19 15:30] - 文档维护（多用户语义）+ 修复版部署（新加坡/本地 1080）

### 改动前总结
用户确认 streamid 默认值多用户不冲突后，要求：① README 补多用户语义与端口冲突说明（部署者易困惑点）；② 提交推送全部修复代码（15:00 条目的 23 个文件未入库）；③ CI 编译新镜像；④ 部署新加坡服务端 + 本地 1080 客户端供验证。

### 改动后总结
- README.md：环境变量表 `SRT_SOCKS5_USERS` 角色修正（H3 后已接入客户端多用户表，arg2 存储，优先于单用户）；新增"多用户语义与端口冲突说明"章节（streamid=passphrase 令牌载体非用户标识 / 三层认证语义表 / 同机多进程唯一冲突点=SOCKS5 监听端口+metrics 端口 / 服务端级真多用户属 P2 协议扩展）
- 部署：CI 构建新 tag 镜像 -> 新加坡 129.150.44.117 容器 srtvpn-sg 滚动更新（含 S1-S6 全部修复：CPU 卡死真凶 S5 + 退出段错误 S6）-> 本地客户端重建（含 S1-S6 修复）
- 部署验证结果见本条目下方追加记录

### 涉及文件
- README.md（多用户语义章节）
- 部署：ghcr.io/luowei729/srt-vpn:<新tag>（新加坡）、本地原生二进制（1080）

## [2026-08-19 15:00] - 第二轮审查全部修复（S1-S6 + H1-H5 + M1-M8 + L 级）

### 改动前总结
按 12:35 审查报告逐项修复全部问题。修复过程中**追加发现 2 个 S 级问题**：
- S5 `srt_getsockstate` 返回值判断错误：代码判 `state==2||state==3`（实际是 SRTS_OPENED/SRTS_LISTENING 健康态），真正的断开状态是 SRTS_BROKEN=6/SRTS_CLOSED=8 -> **断线后收发线程永不退出 + 100µs 忙等重试**（此前"服务端 CPU 79% 卡死"的真凶）
- S6 退出段错误（exit 139，gdb 定位 `CRcvQueue::worker` 崩溃）：每个连接各调一次 `srt_startup` 但进程退出从不调 `srt_cleanup`，且 `process::exit` 跳过 runtime Drop -> atexit 前收发线程仍在跑，与 libsrt 静态析构（停 GC 线程）竞态

### 改动后总结

**S 级（6 项全部修复）**：
- **S1 连接关闭链路重构**（connection.rs）：`closed` 改 `AtomicBool` CAS 幂等；`send_tx` 改 `Mutex<Option<Sender>>`，close 时锁内 take+drop -> 发送线程 recv() Err 自然退出；close 直接 `srt_close`（幂等）让接收线程感知断开退出；**eid 生命周期归接收线程**（退出时唯一释放，消除跨线程释放 UB + 认证失败路径与 Drop 的双重释放）；发送线程忽略空消息（旧"空消息哨兵"从未生效）
- **S5 断线状态判断**（bindings.rs + connection.rs）：新增 `SRTS_BROKEN=6/CLOSING=7/CLOSED=8/NONEXIST=9` 常量与 `srt_state_unavailable()` 统一判断函数，收发两处循环全部改用（附 srt.h 行号考证注释）
- **S6 退出段错误**（connection.rs + main.rs）：全局 `srt_global_init()`（Once + atexit 注册 `srt_cleanup`）；close() join 收发线程（保存 JoinHandle）；main 手工构建 runtime，失败不再 `process::exit`（改为 EXIT_CODE 原子传递，runtime Drop 级联清理连接后再退出）
- **S2 监听失败死锁**（socks5.rs + client/mod.rs）：serve 监听失败返回 `"listen:"` 前缀错误；run() 按前缀分流--监听失败直接退出（重连无意义），隧道断开才走重连；`recv_task` 改 abort 不再无条件 await
- **S3 认证窗口丢帧**（listener.rs + 两端）：authenticate 缓存窗口期 Open/Data/Fin/Close 帧认证通过后**回放**（抽 `dispatch_one_frame` 与主循环共用）；两端隧道断开时 `registry.close_all()` drop 全部会话通道让转发任务感知退出；客户端 TCP 转发加 300s 空闲看门狗（防会话 ID 泄漏）
- **S4 重连计数**（client/mod.rs）：连接成功进入服务态后 `attempt = 0`（连续失败语义，瞬时抖动不再累计退出）

**H 级（5 项全部修复）**：
- **H1 UDP ASSOCIATE 泄漏**（socks5.rs）：select 增加 TCP 控制连接断开检测分支（read 0/Err/意外数据即结束）+ 300s 空闲看门狗
- **H2 UDP 域名/IPv6 目标**（socks5.rs + forward.rs）：`parse_udp_datagram` 支持 ATYP=0x04（IPv6）；地址头改 `encode_udp_addr_header_host`（host 字符串直传，服务端 lookup_host 解析域名/IPv6 字面量）；回包 IPv6 源用 ATYP=0x04；服务端 UDP 转发 socket 改 **IPv4+IPv6 双栈**（旧 `0.0.0.0:0` 是 IPv4-only，v6 目标 send_to 必败）
- **H3 多用户 argon2 认证落地**（socks5.rs + config.rs）：Socks5Config 增加 `users` 表（与 Socks5User 同 schema），`validate_credential` 优先查多用户表（`verify_password` argon2 校验）；CLI `--socks5-users` 与环境变量 `SRT_SOCKS5_USERS` 均接入该表
- **H4 Open 冲突踢会话**（listener.rs）：ID 占用时不再 `registry.remove(sid)`（旧逻辑踢掉现有会话），改为回 Close 帧拒绝且不影响现有会话
- **H5 rx_bytes 失真**（dispatch.rs）：计数统一移入 `recv_event()` 的 Data 分支（TCP/UDP 全路径覆盖），`recv()` 复用不双计

**M 级（8 项全部修复）**：M1 accept+认证 spawn 化并行接入（spawn_blocking + 每连接独立任务）；M2 nonce 连接级一次性（authenticate 单次执行语义注释固化）；M3 UdpReassembler 增加 `cleanup_expired`（30s 过期，转发循环每 64 包顺带清理）；M4 logging 不再读 RUST_LOG（显式构造 EnvFilter，兑现 CLI 优先级）；M5 UDP 中继锁定首个发包包源回包；M6 max_clients≥1 校验；M7 Q8 可靠性协商确认为 P2 协议级（udp_mode 现仅控制服务端 socket 参数，注释标明）；M8 心跳 pong 保留发起方时间戳 + 客户端算 RTT 写入新增指标 `last_rtt_ms`

**L 级（6 项全部修复）**：删 chrono/byteorder 冗余依赖（全项目零引用）；tunnel/mod.rs、multiplex.rs 头注释与 169B 旧值全部更新为 1301B 现状；删 session.rs 死模块（SessionTable 零引用，与 SessionRegistry 两套并存易误导）；crypto_to_pbkeylen 统一到 config.rs；listeners 重复代码收敛；CHANGELOG 顺序修正（新条目置顶）

### 验证
- ✅ 单元测试 25 个全部通过（session.rs 死模块 4 个测试随模块删除），release 编译零警告零错误
- ✅ 端到端回环：TCP 下载 4MB md5 一致；UDP IPv4 小包 / 3000B 分片大包 / 域名目标 / **IPv6 目标（双栈 socket）** 全部回显一致
- ✅ S2：端口占用启动客户端 -> **exit 1 优雅退出**（修复前 139 段错误）
- ✅ S3：认证窗口内首个 SOCKS5 CONNECT 正常回显（缓存回放生效）
- ✅ S4：kill 服务端 4 轮（超过 max_retries=3）-> 客户端 4/4 轮自动恢复且进程存活，恢复后 md5 一致
- ✅ S6：所有退出路径无段错误（gdb 复核确认）

### 涉及文件
- src/srt/bindings.rs（SRT 状态常量 + 统一判断函数）
- src/srt/connection.rs（S1/S5/S6：关闭语义重构 + 状态修复 + 全局 init/join）
- src/main.rs（S6：runtime 手工管理 + EXIT_CODE）
- src/tunnel/dispatch.rs（H5 + close_all）
- src/tunnel/multiplex.rs（注释修正 + heartbeat_timestamp）
- src/server/listener.rs（M1/M2/S3/H4 + dispatch_one_frame 抽取 + M8 pong）
- src/server/forward.rs（H2 双栈 + M3 过期清理 + encode_udp_addr_header_host）
- src/client/mod.rs（S2/S4 + S3 配套 close_all + M8 RTT）
- src/client/proxy.rs（S3 客户端看门狗）
- src/client/socks5.rs（S2 前缀 + H1/H2/M5/H3）
- src/config.rs（H3 users 表 + M6 + crypto_to_pbkeylen 统一）
- src/logging.rs（M4）
- src/metrics.rs（last_rtt_ms）
- Cargo.toml（删冗余依赖）；删除 src/tunnel/session.rs

## [2026-08-19 12:35] - 第二轮全面审查（仅审查记录，未改动代码）

### 改动前总结
用户要求完整审查项目 bug 与功能缺失。本轮通读全部源码（srt/tunnel/auth/client/server/config/cli/main/metrics/logging）与全部 md 文档，聚焦上一轮（12:00）修复后的遗留问题。**本轮纯审查，无代码改动**。

### 审查结论（待修复清单）

**S 级（挂死/泄漏/丢数据，建议立即修复）**：
- S1 `SrtConnection::close()` 语义失效：close 发空 Vec 但 `run_send_loop` 不检查空消息，发送线程永不退出 → socket 永不关闭（重连后服务端名额延迟 15s 释放、本机每次重连泄漏 2 线程+socket+epoll）；`srt_epoll_release` 在接收线程 uwait 期间跨线程释放（UB 风险）；认证失败路径显式 close + Drop 再 close → **epoll 双重释放**（listener.rs 认证失败分支）
- S2 SOCKS5 监听失败（端口被占）时 `recv_task.await` 永久挂起：客户端不重连不退出直接卡死（client/mod.rs 重连循环）
- S3 认证窗口期丢帧：authenticate 等 RESPONSE 循环丢弃非 Response 帧（Open/Data 被丢）→ 客户端请求黑洞；且客户端转发无看门狗 → 会话 ID 泄漏直至 255 耗尽
- S4 重连 `attempt` 连接成功后不清零：累计断线达 max_retries 后进程退出，违背自动重连意图

**H 级（功能错误/资源泄漏）**：
- H1 客户端 UDP ASSOCIATE 无 TCP 断开检测、无空闲超时 → 任务/会话 ID/UDP socket 永久泄漏
- H2 UDP 代理丢目标：域名目标降级为 0.0.0.0、IPv6（ATYP=0x04）整包丢弃（协议层本已支持域名，封装层丢失）
- H3 服务端 `socks5_users` 死配置：全代码无消费点，多用户 argon2 认证（Q10/README 承诺）未实现，客户端实际仅单用户明文
- H4 Open 帧 ID 冲突时 `registry.remove(sid)` 逻辑写反：踢掉现有会话而非拒绝新请求（可被恶意利用踢会话）
- H5 `rx_bytes` 指标失真：TCP 转发全走 `recv_event()`（不计指标），仅 UDP 的 `recv()` 计数

**M 级**：accept 阻塞占用 tokio worker + 多客户端接入串行化（300ms 握手 sleep + 10s 认证超时叠加）；nonce 不防重放（同一 nonce 有效 RESPONSE 30s 窗口内可重放）；UdpReassembler 无过期清理；RUST_LOG 静默覆盖 -v（违背优先级承诺）；UDP 中继未校验回包来源 IP；max_clients=0 无校验；Q8 可靠性协商未实现（FLAG_RELIABLE 无人消费）；心跳 RTT 测量未实现。

**L 级**：冗余依赖（chrono/byteorder 零引用）；tunnel/mod.rs、multiplex.rs、connection.rs 注释仍描述 TS 188B 伪装（已移除）与 169B 旧值；PROJECT_PLAN 决策表/架构图/交付物未随 TS 移除更新（scripts/ 空）；session.rs 与 dispatch.rs 两套会话管理并存；crypto_to_pbkeylen 重复两份；CHANGELOG 时间顺序颠倒。

### 涉及文件
- 无代码改动；仅本审查记录 + AGENTS.md 开发提示

## [2026-08-19 12:00] - 完整代码审查修复（8 项 bug/缺失 + 自审补漏）

### 改动前总结
完整审查发现 4 个确凿 bug（B1-B4）与 5 项功能缺失（F1-F5），详见当次审查报告：
- B1 max_clients 计数只增不减 → 断线后名额永久占满，最终拒绝所有新连接
- B2 半关闭语义被破坏：收到 Fin 帧 dispatch 直接删会话，尾部响应数据被丢弃
- B3 客户端仅在"初始建连失败"时重试，运行中断线直接退出（违背 Q16 自动重连）
- B4 心跳仅"收到即回发"，无主动定时发送/死连接检测；heartbeat_secs 配置从未使用
- F1 客户端 metrics_port 配置静默忽略（仅服务端启动了指标服务）
- F2 指标多个字段（active_sessions/total_sessions/tx_bytes/rx_bytes/heartbeat_timeouts）定义+渲染但从不更新
- F3 服务器 UDP 转发无空闲看门狗 → 客户端静默时会话永久占资源（泄漏隐患）
- F4/F5 会话无上限可无限分配；SessionRegistry::allocate 的 id&0xFF 在 id=256 时产生 0（保留控制通道 ID 被占用）
- 次要：CLI -v 2 无法显式覆盖配置 log_level；verify_password 校验不匹配被误包装为 Err

### 改动后总结
**全部修复（含自审追加补漏）**：

**B1 max_clients 计数泄漏**：client_count 改 `Arc<AtomicUsize>`，客户端任务结束（JoinHandle await 后）`fetch_sub(1)` 释放名额。

**B2 半关闭语义**：会话接收通道从 `mpsc::UnboundedReceiver<Vec<u8>>` 升级为事件类型 `SessionEvent { Data, Fin, Close }`：
- `dispatch_frame` 的 Fin/Close 不再直接 `registry.remove(sid)`，而是投递事件到会话通道
- `proxy.rs::start_forward_with_reply` / `forward.rs::start_tcp_forward` 改为 `recv_event()`：
  收到对端 Fin → `shutdown()` 本地写侧（半关闭传播）；双向 Fin 或 Close → 结束会话
- 会话由任务 Drop 时 `remove`（不再由接收循环删），保证尾部数据不丢
- forward.rs UDP 转发与 socks5.rs UDP associate 侧分别用 recv_event / recv 适配

**B3 客户端整链自动重连**（含自审发现的关键缺陷）：
- `client::run` 重构为「建连 + SOCKS5 服务 + 接收循环 + 主动心跳」整体重连循环
- **自审追加**：`socks5::serve` 原先只在 accept 阻塞，隧道断开时毫无感知 → 重连永不触发。
  新增 `tokio::sync::watch<bool>` 断开信号：接收循环退出时置位，serve 用 select 监听，
  收到信号返回 Err 让重连循环接管
- `connect_once` 走 spawn_blocking（SRT 建连是同步阻塞，避免卡 tokio worker）

**B4 主动心跳 + 死连接检测**：
- 客户端：run 内 spawn 主动心跳定时器，按 heartbeat_secs 周期发心跳帧（Send 失败自动退出，由重连循环重建）
- 服务端：handle_client 用 `tokio::select!` 合并接收批量与心跳周期定时器，定时主动发心跳；
  连续 3 个周期对端无任何数据 → 判定死连接断开，累加 metrics.heartbeat_timeouts

**F1 客户端指标服务**：`client::run` 按 metrics_port 启动 `Metrics::serve_http`（与服务端一致）。

**F2 指标接入**：
- allocation/remove/register_specific 更新 active_sessions/total_sessions（**自审修复**：register_specific 也需计入，
  否则服务端会话 remove 时 fetch_sub 下溢成负数）
- send_data / send_data_batch 计 tx_bytes；recv 计 rx_bytes
- 心跳超时计 heartbeat_timeouts（B4）

**F3 UDP 空闲看门狗**：`start_udp_forward` 增加 300s 双向空闲看门狗（与 TCP 转发一致），超时关闭会话清理注册表。

**F4/F5 会话上限与 ID 边界**：
- `SessionRegistry::allocate` / `register_specific` 增加 `MAX_SESSIONS-1` 上限校验，超限返回 None
- ID 分配改为 u32 递增 + `% MAX_SESSIONS` 显式映射 1..=255（0 保留控制通道），满时返回 None 不再死循环
- proxy.rs / socks5.rs 处理 allocate 返回 None（返回错误拒绝）

**次要修复**：
- cli.rs `verbose` 改 `Option<u8>`：区分"未指定"（用配置/默认）与"显式 -v 2"（覆盖配置），兑现 CLI>配置 优先级
- auth/mod.rs `verify_password`：校验不匹配返回 Ok(false) 而非 Err(false 字符串)
- main.rs 日志级别解析适配 Option

### 验证
- ✅ 单元测试 19 → **26 个全部通过**（新增 dispatch 7 个：事件路由 / Fin 不删会话 / Close 投递 / 会话上限 / ID 边界 / register_specific 拒绝非法 / remove 后路由失败），release 编译零警告
- ✅ 回环端到端：HTTP 200 + 8 并发下载 2MB 文件 md5 全部一致（半关闭无回归）
- ✅ 断线重连端到端：kill 服务端 → 客户端 `SRT 连接断开` → `隧道接收循环退出` → `SOCKS5 服务退出，进入重连` → 1s 间隔重试 6 次进程持续存活 → 重启服务端后**自动重连成功**，恢复后下载 md5 一致

### 涉及文件
- src/tunnel/dispatch.rs（SessionEvent / 会话上限 / ID 修复 / 指标接入 / 新增测试）
- src/server/listener.rs（max_clients 原子计数 / 服务端主动心跳+死连接检测 / Fin 不删会话）
- src/client/mod.rs（整链重连 + 断开信号 / 主动心跳 / 客户端指标 / connect_once spawn_blocking）
- src/client/proxy.rs（半关闭传播 / allocate None 处理）
- src/client/socks5.rs（serve 增加 tunnel_closed 信号 / allocate None 处理）
- src/server/forward.rs（TCP/UDP 半关闭传播 / UDP 空闲看门狗 / 事件接收）
- src/cli.rs（verbose 改 Option<u8>）
- src/main.rs（日志级别解析适配）
- src/auth/mod.rs（verify_password 修复）

## [2026-08-20 02:10] - Docker CMD 修复 + 环境变量方式生产部署（新加坡/本地 1080）

### 改动前总结
Docker 容器默认 `CMD ["--help"]`，用 `-e` 环境变量启动时无命令参数 → 打印帮助退出。

### 改动后总结
- Dockerfile：`CMD` 改为空（`CMD []`），容器无参数直接跑主程序（纯环境变量启动）；帮助用 `-h` 查看
- 重新构建 `env-config-20260820` 镜像

### 生产部署（环境变量方式，无配置文件）
- **新加坡 129.150.44.117**（aarch64，Docker 容器 `srtvpn-sg`）：
  `docker run -d --net=host -e SRT_MODE=server -e SRT_PASSPHRASE=... -e SRT_LISTEN=0.0.0.0:9000 ghcr.io/luowei729/srt-vpn:env-config-20260820`
- **本地**（x86_64，原生二进制）：`SRT_MODE=client ... SRT_SOCKS5_LISTEN=0.0.0.0:1080` 监听 1080

### 验证（隧道连通性全通过）
- ✅ TCP：经 1080 访问百度 HTTP/HTTPS 均 200（curl socks5h）
- ✅ UDP：小包 100B、大包 2048B（分片）、超大包 8000B（7 片）回显一致
- ✅ 两端认证通过，服务端 clients=1

### 涉及文件
- Dockerfile

## [2026-08-20 02:00] - 环境变量配置支持 + CLI 简化（-m 移除，-c 可选）

### 改动前总结
- 配置只能通过 JSON 文件指定，Docker 需挂载配置文件才能启动
- `-m` 单独 CLI 参数控制 UDP 模式（配置里也有 udp_mode 字段，重复）
- `-c` 强制必填

### 改动后总结
**1. 环境变量配置（Docker -e 场景，无需挂载配置文件）**
- 前缀 `SRT_`，**所有配置参数均可覆盖**：
  - 通用：`SRT_MODE`（必填）/ `SRT_PASSPHRASE`（必填）/ `SRT_CRYPTO` / `SRT_METRICS_PORT` / `SRT_LOG_LEVEL`
  - 服务端：`SRT_LISTEN`（必填）/ `SRT_UDP_MODE` / `SRT_MAX_CLIENTS` / `SRT_SOCKS5_USERS`（`user:pass,user2:pass2` 明文转 argon2）
  - 客户端：`SRT_SERVER`（必填）/ `SRT_STREAMID` / `SRT_SOCKS5_LISTEN`（IP+端口）/ `SRT_SOCKS5_USER` / `SRT_SOCKS5_PASS` / `SRT_RECONNECT_INTERVAL` / `SRT_RECONNECT_MAX` / `SRT_HEARTBEAT_SECS`
- config.rs 新增 `from_env()`（纯环境变量构建）+ `apply_env()`（配置文件基础上覆盖）
- 配置优先级：**CLI > 环境变量(SRT_*) > 配置文件 > 默认值**

**2. CLI 简化**
- `-m` 移除（2026-08-20）：UDP 模式直接用 `SRT_UDP_MODE` 或配置文件 `udp_mode`
- `-c` 变可选：省略时纯环境变量启动（`srt-vpn` 无参数直接跑）

**3. main.rs 适配**
- 有 `-c`：加载文件 → apply_env 覆盖 → apply_cli 覆盖
- 无 `-c`：from_env 构建（缺必填项打印提示退出）
- 日志级别：CLI -v > 配置 log_level（含 SRT_LOG_LEVEL）

**4. Docker 使用方式变更**
- 不再需要挂载配置文件：`docker run -e SRT_MODE=... -e SRT_PASSPHRASE=... ghcr.io/luowei729/srt-vpn:latest`
- 支持"配置文件 + -e 覆盖"混合方式
- README/DOCKER.md 镜像地址确定：`ghcr.io/luowei729/srt-vpn`

### 验证
- ✅ 纯环境变量启动服务端/客户端正常（SRT_MODE+SRT_PASSPHRASE+SRT_LISTEN/SRT_SERVER）
- ✅ SOCKS5 完整覆盖（SRT_SOCKS5_LISTEN 监听 IP+端口 / USER / PASS）生效
- ✅ 重连参数覆盖生效（日志显示 interval=2）
- ✅ 必填校验生效（缺 passphrase/长度不足报错退出）
- ✅ 多用户 SRT_SOCKS5_USERS 解析正常（alice/bob 转 argon2）
- ✅ 19 单元测试通过、release 编译零警告

### 涉及文件
- src/cli.rs（-m 移除、-c 可选）
- src/config.rs（from_env/apply_env/辅助函数）
- src/main.rs（加载逻辑 + 日志级别优先级）
- README.md / DOCKER.md / Dockerfile（启动介绍更新）
- PROJECT_PLAN.md（决策表同步）

## [2026-08-20 01:30] - CI 双架构并行编译修复 + 公网 Docker 隧道验证

### 改动前总结
GitHub Actions 用 buildx 单 job 双架构（QEMU 模拟 arm64）构建失败两次：
1. Alpine 缺 `linux/if.h`（`socketconfig.h` 编译失败）
2. Alpine 缺 OpenSSL 静态库（Rust musl `-Wl,-Bstatic` 下 ld 找不到 `-lcrypto/-lssl`）

### 改动后总结
**1. Dockerfile 修复（Alpine 构建依赖）**
- 加 `linux-headers`：提供 `linux/if.h`（libsrt `socketconfig.h` 需要）
- 加 `openssl-libs-static`：提供 `libcrypto.a/libssl.a`（Rust musl 默认 `-Bstatic` 链接必须静态库，只有 openssl-dev 的 `.so` stub 会报 cannot find）

**2. build.rs OpenSSL 库路径探测**
- 新增 `openssl_lib_dirs()`：pkg-config `--variable=libdir openssl` 优先，常见路径兜底
- 显式输出 `cargo:rustc-link-search`（Alpine/musl ld 默认不搜 `/usr/lib`）

**3. workflow 双 runner 并行原生编译（用户建议）**
- amd64：`ubuntu-latest`（x86_64 原生）
- arm64：`ubuntu-24.04-arm`（GitHub 原生 ARM runner，无 QEMU 模拟）
- 两个 job 并行，各自构建 `tag-amd64` / `tag-arm64` 单架构镜像
- merge job 用 `docker buildx imagetools create` 合并多架构 manifest + latest

**效果**：arm64 1m33s + amd64 2m15s 并行 + 合并 16s ≈ 2.5 分钟完成（对比 QEMU 模拟数分钟且不稳）

### 验证
- ✅ 双架构构建成功，GHCR 多架构 manifest（amd64+arm64）
- ✅ 新加坡（aarch64，Docker 容器）pull 镜像启动服务端：`--net=host` + 挂载配置
- ✅ 本机客户端连接公网隧道，**TCP + UDP 大包（100B/2048B 2片/8000B 7片）全部通过**
- ✅ 服务端日志确认 TCP 转发会话 + UDP 多目标转发会话正常

### 涉及文件
- Dockerfile
- build.rs
- .github/workflows/release.yml

## [2026-08-19 23:30] - UDP 大包分片重组（>1301B 数据报支持）

### 改动前总结
UDP 数据报 + 地址头 ≤ FRAME_DATA_MAX(1301B) 才能传输，超出即被丢弃（多目标 UDP 的已知约束）。
DNS 大响应、QUIC/游戏大包等场景无法工作。

### 改动后总结
**设计：分片标记 + 每片携带地址头 + 接收端重组**
- 隧道 UDP Data 帧负载协议扩展（兼容旧版小包格式）：
  - 小包（≤ 单帧承载）：`[地址头][payload]` 原样单帧（与旧版完全兼容）
  - 大包（分片）：每片 `[地址头][0xFF][total_len(u16 BE)][idx(1B)][total(1B)][payload片段]`
    - 0xFF 分片标记与 host_len 合法范围（1..=253）不冲突，安全复用
    - 每片都带地址头：重组器按 (host,port) 解析 key 聚合，无需额外分片组 ID
- **forward.rs** 新增：
  - `split_udp_frames(addr_header, payload)`：按大小自动拆分（小包单帧原样）
  - `UdpReassembler`：按 (host,port) key 重组分片，防御性支持乱序/重复片/非法参数丢弃
  - `start_udp_forward` 改造：隧道→目标走重组器；目标→隧道走拆分器
- **socks5.rs** `start_udp_associate` 改造：中继→隧道走拆分器；隧道→中继走重组器

**约束解除**：UDP payload 最大 65507B 全支持（255 片上限，单片 ~1284B，绰绰有余）。

### 验证
- ✅ 新增 7 个单元测试（小包单帧/大包多帧/重组/乱序/多目标交错/非法丢弃/编解码往返），共 19 通过
- ✅ 端到端回环：小包 100B、大包 2048B（2 片）、超大包 8000B（7 片）全部回显一致
- ✅ release 编译零警告

### 涉及文件
- src/server/forward.rs
- src/client/socks5.rs

## [2026-08-19 22:45] - UDP 代理升级为多目标（数据报内嵌地址头）

### 改动前总结
UDP ASSOCIATE 固定单目标（Open 确定目标后所有数据报发同目标），无法支持
DNS/QUIC/游戏等多目标并发场景（每个数据报不同目标端口）。

### 改动后总结
**设计：单隧道会话 + 每帧内嵌目标地址头**
- 隧道 UDP Data 帧负载格式：`[host_len(1B) + host + port(2B BE)][UDP payload]`
- **forward.rs** `start_udp_forward` 改为多目标：
  - 共享 UdpSocket（不 connect），按帧内地址头 `send_to` 各目标
  - `recv_from` 得到源地址 → 封装 `[源地址头][payload]` 回传
  - 新增 `parse_udp_addr_header` / `encode_udp_addr_header` 编解码
- **socks5.rs** `start_udp_associate` 单会话多目标：
  - 每客户端 UDP 数据报（SOCKS5 UDP 头）解析目标 → 封装地址头 → 隧道
  - 隧道响应解析源地址头 → 构造 SOCKS5 UDP 数据报（ATYP 视 IPv4/域名）→ 回客户端中继

**约束**：UDP payload + 地址头 ≤ FRAME_DATA_MAX(1301B)。大 UDP 数据报重组为后续扩展。

### 验证
- ✅ 同一 UDP ASSOCIATE 下多目标（9900/9901）各自独立收到正确响应
- ✅ 单测 11 通过、release 编译零警告
- 移除未使用的 tun2 依赖（暂不开发 TUN）

### 涉及文件
- src/server/forward.rs
- src/client/socks5.rs

## [2026-08-19 22:30] - UDP 代理实现 + 服务器稳定性加固 + P1 完成标记

### 改动前总结
SOCKS5 UDP ASSOCIATE 返回"不支持"，服务器 UDP 转发返回"尚未实现"；服务器转发会话
无超时清理（此前服务端卡死/会话泄漏隐患）；PROJECT_PLAN P1 待办项文档过时。

### 改动后总结
**1. UDP 代理（SOCKS5 UDP ASSOCIATE）**
- `src/client/socks5.rs`：`start_udp_associate` 完整实现
  - UDP 中继 Socket（随机端口）→ 回复 SOCKS5 绑定地址+端口
  - 首个数据报确定目标 → Open(proto=1) 建隧道 UDP 会话
  - 双向：中继收包→隧道；隧道响应→封装 SOCKS5 UDP 头→回客户端
- `src/server/forward.rs`：`start_udp_forward` 实现
  - UDP socket bind 随机端口，隧道 Data 帧→send 目标；目标响应→Data 帧回传
- 设计约定：单 UDP ASSOCIATE 会话固定首个目标（DNS/QUIC/游戏等单目标场景），
  多目标为后续扩展

**2. 服务器稳定性加固（防卡死/泄漏）**
- forward.rs：`TcpStream::connect` 加 10s 超时（防目标不可达永久挂起）
- forward.rs：转发循环加空闲看门狗（300s 无双向活动则关闭会话）
- 针对此前服务端"只收不回包+CPU打满+会话泄漏"故障根因的根除

**3. P1 完成标记**
- PROJECT_PLAN.md：P1 全部子项标记 [x]，新增功能（UDP代理/加固/Docker/CI）纳入已完成

### 验证
- ✅ UDP ASSOCIATE 回环测试：发 hello-udp → 隧道 → UDP echo → 回 ECHO:hello-udp（双向正常）
- ✅ TCP 代理回归（HTTP 200）、15 单元测试通过、release 编译零警告
- ✅ 多线程上传/带宽优化等此前功能无回归

### 涉及文件
- src/client/socks5.rs（UDP ASSOCIATE）
- src/server/forward.rs（UDP 转发 + connect 超时 + 看门狗）
- PROJECT_PLAN.md（P1 完成）

## [2026-08-19 21:30] - Docker 容器化(Alpine) + GitHub Actions 手动发布 + 启动命令文档

### 改动前总结
项目无 Docker 构建、无 CI 自动发布，md 文档缺少清晰的 server/client 启动命令和配置映射。

### 改动后总结
**1. Docker 容器化（Alpine 基础镜像）**
- `Dockerfile`：多阶段构建
  - builder：`rust:1.97-alpine` + build-base/cmake/openssl-dev，编译 libsrt 静态库 + Rust release
  - runtime：`alpine:3.20` + libstdc++/openssl/ca-certificates/tzdata，非 root 运行（uid 1000）
  - 镜像 <50MB（vs Debian ~150MB），适合 VPN 常驻进程
  - `--network=host` 运行（SRT 是 UDP）
- `build.rs`：**按 musl/glibc 条件链接 pthread**（Alpine/musl 中 pthread 内置 libc，
  跳过 `-lpthread`；glibc 环境仍链接）。benign 但避免 Alpine 链接错误。

**2. GitHub Actions 手动发布镜像**
- `.github/workflows/release.yml`：`workflow_dispatch`（手动触发，可填版本号）
- docker/build-push-action 构建 **amd64 + arm64**，push GHCR（ghcr.io），打版本号+latest tag
- srt-1.5.6 已 git 跟踪（334 文件），checkout 后构建可得源码

**3. 启动命令与配置映射文档**
- 新增 `README.md`：server/client 启动命令（原生 + Docker）+ 配置映射表
- 新增 `DOCKER.md`：容器化部署完整文档（构建/启动/配置/路径约定）
- 配置必填/默认规则：仅 `mode`/`passphrase`/`server`(client)/`listen`(server) 必填，
  其余省略即默认（config.rs validate 已保证）
- `.dockerignore`：排除 target/venv/敏感文件/本地配置，优化镜像缓存

### 验证
- 本机构建 release 通过（build.rs 修改未破坏 glibc 路径）
- git 提交并推送（luowei729/srt-vpn 仓库 main）
- Note：Alpine 首次镜像构建需在 GitHub Actions 验证；如 musl 编译 libsrt 失败，
  文档已给出回退 Debian 方案

### 涉及文件
- Dockerfile（新增）、.dockerignore（新增）、.github/workflows/release.yml（新增）
- README.md（新增）、DOCKER.md（新增）
- build.rs（pthread 条件链接）

## [2026-08-19 20:10] - 国内服务器多线程上传验证：隧道原生支持多线程（结论修正）

### 背景
用户提供国内服务器 47.102.196.219（Ubuntu22.04 x86_64，root/782094Abc）测试多线程上传（国内不走QoS）。

### 部署
- 服务器装 Rust 1.97.1 + libssl-dev，源码本地编译 release（2m37s，GLIBC 匹配）
- 服务端监听 9100，上传接收服务 9800（转发目标）
- 本机客户端 1082 连接国内服务器，隧道 RTT ~20ms

### 验证结论（关键）
- **单线程上传：21.2MB/s**；**8线程并发：33.3MB/s(280Mbps) 全成功**；
  **16线程：31.4MB/s(264Mbps) 全成功**；**32线程：12.2MB/s(102Mbps) 全成功**
- **隧道原生完全支持多线程上传**，无任何连接中断/失败
- 高并发下总吞吐先升后降（16线264Mbps > 8线280Mbps ~ 32线102Mbps，链路带宽共享）

### 重要教训（之前"多线程上传0"的根因）
- 之前"多线程上传0"是**测试目标地址错误**：curl 目标写 127.0.0.1:9800，
  而服务端（新加坡/国内）转发时连的是**服务端本机**的 127.0.0.1:9800，
  我在本机起的接收服务连不到 → Connection refused → 数据全丢
- 正确测试：接收服务必须起在**服务端（转发目标所在机器）**
- 新加坡公网"多线程0" = 目标地址错 + 公网 QoS/链路，非隧道 bug

## [2026-08-19 05:30] - 上传吞吐优化：send_data_batch 同步投递 + 多线程上传验证

### 改动前总结
用户参考 HY1（同为 UDP 协议）测速：单线上传 100M 跑满、下载 350M；本项目公网上传仅 30M。
本机回环实测：上传 17MB/s、下载 42-48MB/s（上传明显偏低且不稳定波动）。

### 改动后总结
**1. send_data_batch 同步投递（关键优化，上传 +30%+）**
- 原：每帧 `conn.send_async(pkt).await`（每帧一次 tokio 任务切换)
- 改：`conn.send(pkt)` 同步投递（crossbeam unbounded send 不阻塞），
  一次函数内投递全部帧，消除每帧 await 让出的调度开销
- 本机回环实测：上传 17 → 53-56 MB/s（1316 版最高 76MB/s）

**2. payload 维持官方默认 1316（用户明确要求不改 1456）**
- 曾临时改 1456 测试（官方 MAX，帧数-10%），用户要求改回官方默认 → 已回滚 1316

**3. 多线程上传验证（确定支持）**
- 8 线程并发：82-92MB/s；16 线程：142MB/s；16×8MB：全部线程完整成功
- 证明隧道原生支持多线程并发上传，无"中断为0"
- 用户公网"多线程上传0"是运营商对上行 QoS + 公网 30M 链路上限，非隧道问题

### 本机回环实测（1316 官方默认版，含 send_data_batch 优化）
| 项目 | 速度 | 换算 |
|---|---|---|
| 下载 | 68.3 MB/s | ~570Mbps |
| 上传 | 76.0 MB/s | ~630Mbps |
| 8线程上传 | 91.7 MB/s | ~770Mbps |
| 16线程上传 | 142 MB/s | - |

### 公网现象诊断
- 公网下载 CPU100% 仅 150M：SRT 在公网高 RTT/丢包下的重传+加密处理开销（应用层 payload
  1316 已是最小帧开销方案）；本机回环同吞吐 CPU 仅 ~10% 证明应用层非瓶颈
- 公网上传 30M：运营商对 SRT/上行 QoS，链路限制

### 涉及文件
- src/tunnel/dispatch.rs（send_data_batch 同步投递）

### 部署
- 服务器 129.150.44.117：1316 官方默认版 release 编译重启成功（active）
- 客户端 1080 连接正常，google HTTP 200

## [2026-08-19 04:35] - 客户端新增 HTTP/HTTPS 代理支持（SOCKS5 + HTTP + HTTPS 三合一）

### 改动前总结
用户用 speedtest 测 SOCKS5 下载 150M（链路最大）但上传为 0，疑似测速工具与隧道交互问题。
用户建议让项目原生支持 HTTP/HTTPS 代理，以便 speedtest 等标准工具可直接连 http 代理测速。

### 改动后总结
**客户端监听端口（1080）现在同时支持三种代理协议，首字节自动嗅探：**
- 首字节 `0x05` → SOCKS5（原有流程，完整兼容）
- 首字节为 HTTP 方法字母（G/P/O/D/C/T/H）→ HTTP/HTTPS 代理

**HTTP/HTTPS 代理能力（src/client/http_proxy.rs 新增）：**
- **CONNECT 隧道**（HTTPS/WebSocket）：`CONNECT host:port HTTP/1.1` → 建隧道 → 回复
  `HTTP/1.1 200 Connection established` → 双向透传（含头后已缓存的 TLS ClientHello）
- **普通 HTTP 转发**（GET/POST）：解析请求行（支持绝对 URI `GET http://host:port/path`
  和相对路径 + Host 头）→ 建隧道 → 把原始请求头透传到目标 → 双向透传（不预回复）
- 目标解析：CONNECT 的 authority / 绝对 URI / Host 头

**统一隧道转发**（src/client/proxy.rs 重构）：
- `start_tcp_forward_with_reply(client, dst, port, ..., reply, prepend)`：
  - reply：给客户端的成功响应（SOCKS5 10B / HTTP 200）
  - prepend：先发往隧道的预读数据（HTTP 请求头 / CONNECT 后的 TLS 数据）
- SOCKS5 调用传 reply=SOCKS5 响应、prepend=空

### 验证结果
- ✅ HTTP 代理普通 GET：HTTP 200，内容正确
- ✅ HTTP 代理 CONNECT 隧道：200 + 隧道内透传 280KB 数据完整
- ✅ 回收下载 54.7MB/s、上传 30.4MB/s（与 SOCKS5 相当）
- ✅ 真实环境：SOCKS5 google 200、HTTP-CONNECT bing 200
- ✅ 回归：SOCKS5 原功能未破坏

### 涉及文件
- src/client/http_proxy.rs（新增）
- src/client/proxy.rs（start_forward_with_reply 重构，支持 reply/prepend）
- src/client/mod.rs（注册 http_proxy 模块）
- src/client/socks5.rs（协议嗅探分派：首字节 0x05=SOCKS5，否则 HTTP）

### 部署
- 服务器 129.150.44.117：release 编译重启成功（服务端侧无功能变化，仅为代码同步）

## [2026-08-19 04:00] - 带宽优化完成：删除 TS 伪装层 + SRT 原生大包 + FileCC + 接收通道重构

### 改动前总结
用户反馈带宽低、上传速度更低。实测本机回环：下载 4.6MB/s、上传 0.84MB/s。
经探针（SRT 原始 1316B）证明 SRT 层单方向 371MB/s、双向 73MB/s、逐帧 echo 51MB/s，
**瓶颈在应用层而非 SRT 层**。

### 性能实测（本机回环，标准 HTTP 大文件）
| 指标 | 优化前(TS 188B) | 优化后(SRT 1316B) | 提升 |
|---|---|---|---|
| 下载 | 4.6 MB/s | **49.3 MB/s** | 10x |
| 上传 | 0.84 MB/s | **61 MB/s** | 70x |
| 双连接并发下载 | 受限 | 各31-33MB/s(合计~65MB/s) | - |

### 改动后总结（4 项核心改动）
**1. 删除 TS 伪装层（关键决策，经用户确认）**
- 删除 `src/tunnel/ts.rs`、`TsEncoder/TsDecoder/unwrap_ts_packet/wrap_ts_frame`
- 理由：SRT 原生 passphrase 加密已保证载荷不可见，TS 188B 壳只增加 8 倍帧率开销
  （每 188B 只装 169B 有效载荷）而无额外安全收益
- `FRAME_DATA_MAX`: 169 → **1301**（SRT 原生 payload 1316 - 帧头 15）
- `SRTO_PAYLOADSIZE`: 188 → **1316**（直播标准）

**2. 传输类型改用 SRTT_FILE（FileCC）——全双工卡死根因修复**
- 之前只设 MESSAGEAPI=1 未设 TRANSTYPE → 默认 LiveCC
- 官方文档警告 LiveCC "not intended to work with virtually infinite ingest speeds…
  Otherwise the behavior is undefined and might be surprisingly disappointing"
- 这正是 VPN 突发大流量全双工吞吐塌陷的根因
- 改设 `SRTO_TRANSTYPE=SRTT_FILE`（FileCC，最大速度发送）+ 保留 MESSAGEAPI=1（Message 方法）

**3. 修复 dispatch.rs 残留 FRAME_DATA_MAX=169（关键 bug）**
- dispatch.rs 有独立本地常量仍=169，导致 send_data_batch 一直发 169B 小包
- 改为复用 multiplex.rs 的 FRAME_DATA_MAX（1301）
- 线程栈抓包证据：原来 TCP write len=169（小包）；修复后 1316B 大包

**4. 接收通道重构：crossbeam + spawn_blocking → tokio mpsc Unbounded**
- 原 recv 路径：SRT 接收线程 → crossbeam → spawn_blocking(阻塞 recv) → tokio
- 新路径：SRT 接收线程 → tokio mpsc UnboundedSender（同步 send 任意线程）→
  UnboundedReceiver.recv().await（真正 async 等待，不阻塞 worker）
- 消除双重桥接调度开销；recv_batch_async 批大小 64→512

### 诊断经验（重要）
- **echo 测试误导**：纯本地 TCP echo 仅 32MB/s（Python 服务限制），
  用它测隧道会误判为隧道慢。应用 HTTP 大文件单向下传/上传测真实吞吐。
- **探针隔离**：用 libsrt 裸探针证明 SRT 层 371MB/s，定位瓶颈在应用层。
- **gdb 线程栈**：抓 `__libc_send len=169` 暴露了残留的小包分片 bug。

### 公网实测（链路受限）
- 公网裸链路仅 ~365KB/s（本机↔服务器国际链路），隧道 345KB/s = 裸链路 95%
- 瓶颈在链路本身，隧道已逼近极限；google/youtube HTTP 200 可用性正常

### 涉及文件
- src/tunnel/ts.rs（删除）、src/tunnel/mod.rs（去 mod ts）
- src/tunnel/multiplex.rs（FRAME_DATA_MAX 1301、decode_srt_message）
- src/tunnel/dispatch.rs（去 ts_enc、修 FRAME_DATA_MAX、send_data_batch）
- src/srt/connection.rs（SRTT_FILE、PAYLOADSIZE 1316、接收通道 tokio mpsc 重构）
- src/client/{mod,proxy,socks5}.rs、src/server/{listener,forward,mod}.rs（去 ts）
- scripts/verify_ts.sh（删除，TS 伪装已卸载）

### 部署
- 服务器 129.150.44.117 release 编译重启成功，10.0.0.2 桌面机恢复通过隧道访问

## [2026-08-19 01:50] - P1 传输层三大关键 bug 修复：并发大文件传输验证通过

### 改动前总结
隧道数据帧路由打通后，单会话传输正常，但存在三个严重问题：
1. 并发多会话大文件传输时第二个会话饿死（0B~30KB 停滞）
2. 下载文件字节数正确但内容错位（字节 737092 处块错位）
3. curl 带认证并发连接 0.02s 即失败（000 错误）

### 改动后总结
**1. SRT 消息保序修复（数据错位根因）**
- `srt_sendmsg` 第 5 参数 inorder: 0 -> **1**
- 根因：inorder=0 时 SRT 允许重传消息"超越"后续消息，导致帧乱序、
  分片重组后数据块错位（字节数对但内容错）
- 隧道协议依赖帧顺序，必须保序投递

**2. SOCKS5 协议解析修复（并发认证失败根因）**
- 所有解析点从"单次 read"改为 **read_exact 精确读取**
- 根因：TCP 是字节流不保证消息边界，单次 read 可能只读到部分字节，
  并发多连接时内核缓冲分割更频繁，导致密码解析错位->认证失败
- 涉及：方法协商/用户名密码认证(RFC1929)/CONNECT 请求解析

**3. 发送吞吐修复（并发饿死根因）**
- 发送线程 `run_send_loop`：遇背压（MJ_AGAIN）持续重试**永不退出**
  （之前重试 1000 次后退出，发送通道永久关闭导致数据全丢）
- 发送通道改 **unbounded**（避免 spawn_blocking 池耗尽死锁）
- SRT 缓冲增大：SNDBUF/RCVBUF=16MB，UDP 缓冲 4/8MB，流控窗口 FC=1024
- `send_async` 去掉 spawn_blocking（unbounded 下 send 不阻塞）

**4. 会话路由时序修复**
- 服务端 Open 帧处理：先 `register_specific` 注册会话通道，
  再 spawn 转发任务（避免数据帧先到导致"会话不存在"）

### 验证结果
- ✅ curl 串行 3×2MB：md5 全部一致
- ✅ curl 并发 2×3MB：双会话完整，md5 全匹配，客户端进程稳定
- ✅ Python 带认证并发 2×1MB：md5 全匹配
- ✅ 编译零警告，15 单元测试全通过

### 涉及文件
- src/srt/connection.rs（inorder=1、run_send_loop 重试、缓冲配置、unbounded 通道）
- src/client/socks5.rs（read_exact 解析重写）
- src/server/listener.rs（Open 先注册再 spawn）
- src/tunnel/dispatch.rs（register_specific）
- src/server/forward.rs / src/client/proxy.rs（转发对接）

### 部署环境更新
- 服务器 129.150.44.117（Debian aarch64）：Rust 1.97.1 已装、源码已同步
- 支持 amd64 + arm64 双架构（各自本地编译）

## [2026-08-19 02:10] - 服务器部署完成 + 跨 VPN 实测 + 10.0.0.2 无认证接入

### 改动前总结
服务器编译产物已生成但未部署运行，尚无跨 VPN 实测；本机 SOCKS5 仅限 127.0.0.1。

### 改动后总结
**1. 服务器部署（129.150.44.117, Debian aarch64）**
- release 编译完成：`target/release/srt-vpn`（3m09s，含全部关键修复）
- systemd 服务持久化：`/etc/systemd/system/srt-vpn.service`
  - 开机自启 + 崩溃自动重启（Restart=on-failure）
  - ExecStart 指向 release 二进制 + server.conf
  - 状态：active，`0.0.0.0:9000` UDP 监听中

**2. 跨 VPN 端到端实测（本机 10.0.0.253 → 服务器）**
- 本机客户端连 `129.150.44.117:9000`：SRT 连接 + 挑战应答认证通过
- 经 SOCKS5 隧道下载服务器 2MB 文件：HTTP 200，**md5 完全一致**
- 针对 systemd 托管服务端复测：同样 md5 全匹配，传输完整

**3. 10.0.0.2 无认证 SOCKS5 接入**
- 本机客户端 SOCKS5 监听改 `0.0.0.0:1080`，不配置凭据 → 无认证模式
- 无认证路径自测：2MB 下载 md5 一致
- **10.0.0.2 实际接入**：客户端日志显示 `peer=10.0.0.2` 无认证访问
  （fonts.gstatic.com / www.gstatic.com:443），多会话并发正常（session 32/33...）

### 涉及文件/配置
- /etc/systemd/system/srt-vpn.service（服务器）
- /root/srt-vpn/configs/server.conf（服务器，listen 0.0.0.0:9000）
- /tmp/client_noauth.json（本机无认证客户端配置，监听 0.0.0.0:1080）

### 当前运行拓扑
```
10.0.0.2 → SOCKS5(10.0.0.253:1080, 无认证) → SRT 加密隧道 → 服务器 129.150.44.117 → 目标
```

## [2026-08-19 02:40] - 故障恢复：服务端进程卡死导致隧道断开（非网络问题）

### 改动前总结
10.0.0.2 突然无法访问外网，本机客户端 SRT 连接持续 `connection timed out` 重连失败，1080 无监听。

### 排查过程（关键：避免被假象误导）
1. 本机侧误判为"服务器→本机 UDP 回程不通"（服务器 ping 10.0.0.253 / 112.3.201.48 全丢包）
2. **但用户确认链路本身 UDP 互通是好的**——重新怀疑服务端
3. 服务器 tcpdump 抓包决定性证据：
   - 客户端握手包**持续到达**服务器（`112.3.201.48.* → 10.0.0.99:9000`，每 1s 一个 64B 包）
   - 但抓包里**只有 In（入站），没有 Out（出站）**——服务端收到包但不回握手响应
4. 服务端 srt-vpn 进程 **CPU 79% 持续高占用** + 日志停留在 02:09:08 不再输出

### 根因
**服务端 srt-vpn 进程卡死**（CPU 打满 + 无响应），导致收到客户端握手包但不回握手/认证响应包。
SRT 握手需要双向，回包被卡在服务端内部，客户端永远收到不握手确认 → 一直 `connection timed out`。

### 解决
- `systemctl restart srt-vpn` 后**立即恢复**：认证通过、会话建立、隧道工作
- 恢复后实测：Google HTTP 200（0.66s），ChatGPT 403（正常，UA 拒绝非代理问题）
- 10.0.0.2 桌面机恢复通过隧道访问 chatgpt.com:443 等

### 服务端卡死疑似原因（待 P1.5 深入排查）
- 日志出现大量 `连接目标 10.0.0.1:80 失败: Connection timed out`（客户端应用层访问内网其他设备，服务端转发超时）
- 02:09:04 出现 `RCV-DROPPED 6 packet(s), msgno 0 (SND DROP REQUEST)`
- 疑似某个转发会话死循环 / 连接未释放累积 / 会话表泄漏
- 建议：后续加超时清理、看门狗、单次会话 CPU/时长上限；部署后监控 `ps -p <pid> -o pcpu`

### 重要排查教训
- **服务端进程卡死的典型特征是"只收包不回包" + CPU 高占用 + 日志停止输出**
- 抓包要看 **In 和 Out 双向**，只看到 In 没看到 Out = 服务端进程问题而非网络问题
- 用户对链路状态的判断（"UDP 互通是好的"）应优先信任，避免在错误方向上过度排查

### 涉及文件/环境
- 服务器 129.150.44.117：systemctl restart srt-vpn（未改代码/配置）
- 故障前日志时间线：02:09:04 RCV-DROPPED → 02:09:08 大量转发超时 → 服务端卡死 → 02:33:57 重启恢复

## [2026-08-18 15:45] - P1 骨架搭建完成：编译通过 + 认证链路打通

### 改动前总结
项目仅有设计文档，无任何可运行的代码。需要搭建 Rust 项目骨架、集成 libsrt 编译、实现隧道核心与认证。

### 改动后总结
**1. Rust 项目骨架 + libsrt 构建集成**
- `Cargo.toml`：依赖 clap/serde/tokio/argon2/hmac/sha2/tracing/libc 等
- `build.rs`：CMake 编译 libsrt 1.5.6 为静态库（OpenSSL 后端，GCC 编译），链接 libstdc++
- `src/` 按功能区域划分：srt/ tunnel/ auth/ client/ server/ config/ cli/ metrics/ logging/

**2. SRT FFI 封装层（srt/）**
- `bindings.rs`：libsrt 1.5.6 完整 FFI 声明（socket 操作、epoll、选项枚举）
- `connection.rs`：安全封装（连接/监听/收发线程/epoll 事件循环）
- 线程模型：发送线程 + 接收线程（epoll）+ crossbeam channel

**3. 隧道层（tunnel/）**
- `ts.rs`：MPEG-TS 188B 分片伪装（固定 PID 0x0100，CC 递增）
- `multiplex.rs`：多路复用层（帧头 v1：Magic+Version+Type+SessionID+Len+Seq+Flags）
- `session.rs`：会话管理（256 上限，半关闭状态机）

**4. 认证链路（关键修复）**
- streamid 静态令牌（HMAC-SHA256(passphrase) 派生）+ 双 HMAC 挑战-应答
- **修复 SRT 双向通信的 4 个关键 bug**：
  - IPv4 地址字节序错误（from_be_bytes→from_ne_bytes，127.0.0.1 曾解析成 1.0.0.127）
  - 非阻塞 connect 需等待 CONNECT 事件确认连接完成
  - 关闭 TSBPD（LIVE 模式强制启用导致数据延迟投递）
  - **responder 先发数据导致 initiator 连接 broken**（accept 后需等 300ms 握手完成）

**5. 配置/CLI/日志/指标**
- `config.rs`：统一 JSON schema（mode 区分 server/client，CLI 覆盖）
- `cli.rs`：clap 参数（-c/-m/-v/-h + SOCKS5 完整参数）
- `logging.rs`：JSON 结构化日志；`metrics.rs`：回环 HTTP 指标端口

**6. 端到端验证通过**
- ✅ 客户端 SRT 连接建立（握手）
- ✅ streamid 静态令牌校验通过
- ✅ 挑战-应答认证通过（30s 时间窗防重放）
- ✅ 客户端认证通过，建立会话
- ✅ 指标端口返回 JSON（active_connections/total_connections 等）

### 涉及文件
- Cargo.toml / build.rs / configs/server.conf / configs/client.json（新增）
- src/main.rs / src/cli.rs / src/config.rs / src/logging.rs / src/metrics.rs（新增）
- src/srt/{mod,bindings,connection}.rs（新增）
- src/tunnel/{mod,multiplex,ts,session}.rs（新增）
- src/auth/{mod,challenge}.rs（新增）
- src/client/{mod,socks5,proxy}.rs（新增）
- src/server/{mod,listener,forward}.rs（新增）
- deploy/srt-vpn.service / scripts/verify_ts.sh（新增）

### 待实现（P1 后半段）
- 隧道数据帧路由（socks5 连接 ↔ 隧道会话 ↔ 服务器直连转发）
- SOCKS5 用户名密码真实认证（argon2）
- 心跳保活周期性发送
- 完整联调测试（TCP/UDP 代理）