- 请使用中文回复 思考也要使用中文 永远使用中文
- 首先阅读AGENTS.md 确保阅读过项目所有md
- 维护项目的所有md文档，有些文档内容可能过时要分辨
- 要求代码里每步都要中文注释功能的实现和实现的原因，为后期排查问题和开发做好基础
- 按照项目代码功能结构,功能区域划分规则，进行开发修改，不要擅自改变代码架构和功能划分结构。
- 你先规划架构，不明白的细节可以先和我提问确认，再写代码，你开发阶段可以打开 无头 chrome 访问主站页面调试验证。
- 每次写代码前先给"改动前总结"，写完后给"改动后总结
- 每次更改变动要按照格式中文写入项目对应根目录下的AGENTS.md CHANGELOG.md DEPLOY_CREDENTIALS.md PROJECT_PLAN.md记录写入北京时间和日期，方便后期再开发修改的时候快速定位
- 把在本项目需要长期记住的开发提示，写到本文件的下方，记录写入北京时间和日期

---
开发提示如下：
- [2026-08-18 10:30] 项目正式启动：SRT-VPN（基于 SRT 协议的 VPN）。libsrt 1.5.6 源码在 srt-1.5.6/（静态编译+FFI），Rust 项目在根目录。完整 24 项架构决策见 PROJECT_PLAN.md 第二节，任何后续开发先查该表避免偏离共识。
- [2026-08-18 10:30] 隧道协议要点：单 SRT 连接 + 多路复用层（帧头 v1，u16 会话 ID，256 上限）；单层可靠模型（重传交给 SRT，复用层只做分帧/调度/窗口流控）；所有帧（含 ACK）统一封装为 188B MPEG-TS 包保持伪装一致；-m 服务端配置 UDP 可靠/尽力而为，握手协商。
- [2026-08-18 10:30] 认证要点：SRT passphrase 原生加密（aes-128 默认）+ streamid 静态令牌 + 双 HMAC 挑战-应答（30s 时间窗防重放）。认证失败 P1 断开+告警，P2 加黑名单。
- [2026-08-18 10:30] 客户端入口顺序：P1 仅 SOCKS5（用户名密码认证，多用户 argon2 哈希，监听可配），P2 接入 TUN（tun2 crate 4.0.0，客户端跨平台 Linux/Win/macOS；服务器仅 Linux）。
- [2026-08-18 10:30] 工程约定：JSON 结构化日志 + 回环 HTTP 指标端口；心跳 5s + 客户端自动重连；单端口数据+信号共存；P1 交付含 ffprobe 验证脚本（TS 伪装真实性）。
- [2026-08-18 10:30] 目录约定：srt-1.5.6/ 是 libsrt 官方源码不动它（构建脚本引用），Rust 代码按 src/ 功能区域划分（srt/ 隧道/ auth/ client/ server/），改动不得擅自改变功能结构。
- [2026-08-18 15:45] P1 骨架完成，认证链路打通。**SRT 双向通信 4 个关键 bug 教训**（connection.rs）：
  1. IPv4 地址必须用 `u32::from_ne_bytes(octets)` 而非 from_be_bytes，否则 127.0.0.1 会变 1.0.0.127
  2. 非阻塞 connect 返回 0 只是"连接已发起"，必须用 epoll 等 `SRT_EPOLL_CONNECT`(0x4) 事件确认完成再收发
  3. 不用 `SRTO_TRANSTYPE_LIVE`（会强制 TSBPD 导致数据延迟投递），手动设 MESSAGEAPI=1 + TSBPDMODE=0
  4. **responder(服务端) accept 后必须等 ~300ms 握手完全完成再发数据**，否则 initiator 收到数据时连接被标记 broken（"Connection was broken"）
- [2026-08-18 15:45] 收发线程模型：接收线程用 epoll(IN|ERR) + `srt_epoll_uwait`，**线程启动时要先非阻塞捞取 epoll 注册前已缓冲的数据**（否则握手后立即到达的数据不会补触发 IN 事件）。libsrt 是 C++ 库，build.rs 链接需 `libstdc++`。
- [2026-08-18 15:45] 验证方法：libsrt 问题先用最小 rustc/独立 bin 探针隔离（排除应用层干扰）。加密/非阻塞/epoll 生命周期/线程模型都验证过非根因，最终定位是握手完成时机。
- [2026-08-19 01:50] **传输层三大血泪教训**：① `srt_sendmsg` 第5参数 inorder 必须=1（=0 重传消息可超越后续消息->帧乱序->数据块错位，字节数对但内容错）；② TCP 流协议解析必须 read_exact（单次 read 假设消息完整在并发时必炸，SOCKS5 认证错位根因）；③ 非阻塞 sendmsg 返回 -1 是背压（MJ_AGAIN），发送线程必须重试而非退出（退出=发送通道永久关闭=数据全丢）。
- [2026-08-19 01:50] 吞吐配置：发送通道 unbounded+发送线程自我调速；SRT 缓冲 SNDBUF/RCVBUF=16MB、UDP 4/8MB。（注意：recv_async 用 spawn_blocking 桥接的旧做法已在 04:00 重构淘汰，见下方 04:00 条目）
- [2026-08-19 01:50] 部署拓扑：本机 10.0.0.253=开发/客户端(x86_64)，服务器 129.150.44.117=服务端(Debian aarch64，SSH root/782094Abc)。双架构 amd64+arm64 各自本地编译（不交叉编译）。测试脚本陷阱：`(cmd; echo $?) &` 子 shell 竞态误报、源文件提前 rm 导致 cmp 误判，用显式 PID+md5 对比。
- [2026-08-19 02:40] **故障排查核心教训：服务端进程卡死 = 只收包不回包 + CPU 打满 + 日志停止输出**（2026-08-19 隧道突然全断的根因）。① 服务器 tcpdump 抓包要看 In 和 Out 双向，只有 In 无 Out 且 CPU 高 = 服务端进程卡死（本次就是 srt-vpn CPU 79% 持续高占用、日志停在 02:09），并非网络问题；② 用户对链路状态（UDP 互通是好的）的判断应优先信任，避免在错误方向过度排查；③ 处理方式 `systemctl restart srt-vpn` 立即恢复。卡死疑似根因：转发会话（如访问内网 10.0.0.1:80 超时）死循环/会话表泄漏/RCV-DROPPED 累积，P1.5 需加超时清理+看门狗+会话泄漏监控。
- [2026-08-19 02:40] 可用备用测试机：东京 154.19.186.38（root/782094Abc，本机可直连 63ms），主服务器 129.150.44.117 故障时可作中转/替代。另：本机公网出口 NAT 为 112.3.201.48（中国移动上海，回程此前疑似有问题，本次证明是误判）。
- [2026-08-19 04:00] **带宽优化 4 大关键教训（本机回环吞吐 4.6/0.84→49/61 MB/s）**：① TS 伪装层删除（SRT 加密已保载荷不可见，TS 壳只增 8 倍帧率开销），FRAME_DATA_MAX 169→1301；② **必须设 SRTO_TRANSTYPE=SRTT_FILE（FileCC）**，否则默认 LiveCC 在 VPN 突发大流量下 behavior undefined 导致全双工卡死；③ **多个文件各自定义 FRAME_DATA_MAX 会导致残留旧值小包**（dispatch.rs 曾残留 169），统一复用 multiplex.rs 常量；④ **接收通道用 tokio mpsc Unbounded 代替 crossbeam+spawn_blocking**（接收线程直接 send 到 UnboundedSender，消除双重桥接调度开销）。
- [2026-08-19 04:00] **测速方法论**：echo 一收一回测试会被 TCP 往返+Python 服务限制误导（本地 echo 也仅 32MB/s）；应用 HTTP 大文件单向下传/上传测真实吞吐；探针用 libsrt 裸 sendmsg 隔离应用层；本机回环 49/61MB/s，公网受链路 ~365KB/s 限制（隧道达链路 95%）。
- [2026-08-19 04:35] **客户端三合一代理（SOCKS5+HTTP+HTTPS）**：监听端口首字节嗅探——0x05=SOCKS5，HTTP 方法首字母（G/P/O/D/C/T/H）=HTTP 代理。http_proxy.rs 支持 CONNECT 隧道（回 200 后透传，含头后 TLS 数据）+ 普通 HTTP（透传请求头）。proxy.rs 的 start_forward_with_reply(reply, prepend) 统一建隧道：reply=给客户端的成功响应，prepend=先发隧道的预读数据。测速注意：官方 speedtest CLI 无 --proxy 参数也不认 http_proxy 环境变量，需用 proxychains 或支持代理的工具连 http 代理。
- [2026-08-19 05:30] **send_data_batch 同步投递优化**：逐帧 `send_async().await`（每帧 tokio 切换）改为 `send()` 同步投递（crossbeam unbounded 不阻塞），本机上传 17→76MB/s。**payload 用官方默认 1316，用户明确不用 1456**。**多线程上传已证明支持**（8线程 92MB/s、16线程 142MB/s、16×8MB 全完整），用户公网"多线程上传0"是上行 QoS/链路限制。公网下载 CPU100% 是 SRT 高RTT重传开销，应用层非瓶颈（本机同吞吐 CPU 仅10%）。
- [2026-08-19 20:10] **国内服务器多线程验证（47.102.196.219, Ubuntu22.04 x86_64, root/782094Abc）+ 测速陷阱**：隧道原生支持多线程（单线21MB/s、8线33MB/s、16线31MB/s、32线全成功）。**关键测速陷阱：curl 目标写 127.0.0.1:9800 时，服务端转发连的是【服务端本机】的9800，接收服务必须起在服务端机器上**，否则 Connection refused 导致"上传0"假象（此前用户"多线程上传0"由此导致，非隧道bug）。国内服务器部署：装Rust+libssl-dev本地编译（GLIBC匹配）。
- [2026-08-19 21:30] **Docker容器化 + CI**：Dockerfile 多阶段 Alpine（rust:1.97-alpine + alpine:3.20 runtime，镜像<50MB，--net=host 运行）；build.rs 按 musl/glibc 条件链接 pthread；.github/workflows/release.yml 手动触发（workflow_dispatch）构建 amd64/arm64 push GHCR；README.md/DOCKER.md 写明月启动命令+配置映射（仅 mode/passphrase/server(listen) 必填，其余默认）；仓库 github.com/luowei729/srt-vpn，本地 git 提交推送 main。
- [2026-08-19 21:40] **已停止所有手动测试服务，后续统一用 Docker 跑**：
  - 本机：所有 srt-vpn 进程、1080/1081/1082 代理、回环测试、Python 测试服务（9800/9900）已全部清理
  - 新加坡 129.150.44.117：systemctl stop+disable srt-vpn，9000/9800 已停（保留部署文件，可随时 systemctl start）
  - 阿里云 47.102.196.219：srv_cn 服务端(9100) + 上传接收(9800) 已停（保留编译产物 /root/srt-vpn-src）
  - Docker 测试流程：`docker build -t srt-vpn:local .` 后 `--net=host -v <config>:/app/configs/x.conf:ro -c /app/configs/x.conf`
  - 云端 Docker 镜像：GitHub Actions 手动触发 push GHCR 后拉取运行
- [2026-08-19 22:30] **P1 完成 + UDP 代理 + 稳定性加固**：① SOCKS5 UDP ASSOCIATE 已实现（socks5.rs start_udp_associate：中继 socket + 首包定目标 + Open(proto=1)），服务器端 start_udp_forward（UDP socket 双向）；② 服务器稳定性加固：TcpStream::connect 10s 超时 + 转发空闲 300s 看门狗（防此前卡死/泄漏根因）；③ PROJECT_PLAN P1 全部标记完成。UDP 隧道回环已验证（发/收 ECHO 双向正常）。
- [2026-08-19 22:45] **UDP 代理多目标版**：单隧道会话 + 每帧内嵌地址头 `[host_len(1B)+host+port(2B BE)][payload]`；服务器共享 UdpSocket 按帧内目标 send_to、recv_from 源地址回传；客户端每数据报解析 SOCKS5 UDP 头目标封装地址头发送、响应解析源回传。约束 payload+头≤1301B。验证多目标(9900/9901)各自正确响应。**多目标 UDP 协议要点**：UDP Data 帧负载=地址头+UDP payload（区别于 TCP 纯 payload）。
- [2026-08-19 23:30] **UDP 大包分片重组**（解除 1301B 约束，支持至 65507B）：协议扩展——大包每片 `[地址头][0xFF][total_len u16BE][idx][total][payload片段]`，**每片都带地址头**（重组器按 (host,port) key 聚合，无需分片组 ID）；0xFF 标记与 host_len 合法范围(1..=253)不冲突。forward.rs 新增 split_udp_frames（小包原样单帧兼容旧版）+ UdpReassembler（防御乱序/重复片/非法参数）；start_udp_forward 与 start_udp_associate 收发两侧接拆分/重组。验证：19 单测 + 端到端 100B/2048B(2片)/8000B(7片) 回显一致。
- [2026-08-20 01:30] **CI 双架构并行编译 + Alpine 构建依赖**：① **Alpine 编译 libsrt 需 `linux-headers`**（srtcore/socketconfig.h 包含 linux/if.h，缺报 fatal error）+ **`openssl-libs-static`**（Rust musl 默认 -Wl,-Bstatic 必须静态库，只有 openssl-dev 的 .so stub 报 cannot find -lcrypto/-lssl）；② build.rs 用 pkg-config `--variable=libdir openssl` + 常见路径兜底输出 `cargo:rustc-link-search`（musl ld 默认不搜 /usr/lib）；③ **workflow 双 runner 并行原生编译**：amd64=ubuntu-latest、arm64=ubuntu-24.04-arm（GitHub 原生 ARM runner 免 QEMU 模拟），各构建 tag-amd64/tag-arm64，merge job 用 `docker buildx imagetools create` 合并多架构 manifest + latest——总耗时 ~2.5min（arm64 1m33s 并行）。GHCR 镜像：ghcr.io/luowei729/srt-vpn:<tag>（新加坡 aarch64 已验证 pull+运行+公网隧道测试全通过）。
- [2026-08-20 02:00] **环境变量配置 + CLI 简化**：① **配置优先级 CLI > SRT_* 环境变量 > 配置文件 > 默认**；② 全部配置参数可 -e 覆盖（config.rs from_env 纯环境变量构建 / apply_env 文件基础上覆盖）：通用 SRT_MODE/SRT_PASSPHRASE/SRT_CRYPTO/SRT_METRICS_PORT/SRT_LOG_LEVEL，服务端 SRT_LISTEN/SRT_UDP_MODE/SRT_MAX_CLIENTS/SRT_SOCKS5_USERS(明文转argon2)，客户端 SRT_SERVER/SRT_STREAMID/SRT_SOCKS5_LISTEN(IP+端口)/SRT_SOCKS5_USER/SRT_SOCKS5_PASS/SRT_RECONNECT_INTERVAL/SRT_RECONNECT_MAX/SRT_HEARTBEAT_SECS；③ **-m 已移除**（UDP 模式用 SRT_UDP_MODE 或配置 udp_mode）；④ **-c 变可选**（省略=纯环境变量启动）；⑤ **Docker 无需挂载配置文件**：`docker run -e SRT_... ghcr.io/luowei729/srt-vpn:latest`（支持文件+-e混合）。日志级别优先级：CLI -v > 配置 log_level。
- [2026-08-20 02:10] **生产部署（环境变量方式）+ Docker CMD 修复**：① Dockerfile `CMD []`（默认不再 --help，纯环境变量启动；帮助用 -h）；② 新加坡容器 `srtvpn-sg`（aarch64, --net=host, -e 指定 SRT_MODE/PASSPHRASE/LISTEN）+ 本地客户端监听 0.0.0.0:1080（SRT_SOCKS5_LISTEN 指定）已部署运行；③ 验证：经 1080 隧道访问百度 HTTP/HTTPS 200 + UDP 100B/2048B/8000B 全通过。镜像 tag：ghcr.io/luowei729/srt-vpn:env-config-20260820。
- [2026-08-19 12:00] **完整审查 8+ 项修复**：① **B1 max_clients 泄漏**——client_count 用 Arc<AtomicUsize>，客户端任务结束 fetch_sub 释放名额（只增不减会永久拒绝新连接）；② **B2 半关闭语义**——会话通道改 `SessionEvent{Data,Fin,Close}` 事件型，dispatch_frame 的 Fin/Close 投事件不删会话（原直接 remove 会丢尾部数据），转发任务收到 Fin → shutdown 本地写侧，双向 Fin 或 Close 才结束；③ **B3 整链自动重连**——client::run 把「建连+SOCKS5+接收循环+心跳」整体放重连循环；**关键：socks5::serve 原只在 accept 阻塞，隧道断开无感知→重连永不触发！** 加 `watch<bool>` 断开信号：recv_loop 退出置位，serve select 信号停止 accept 返回 Err 让重连接管（端到端验证 kill server→自动重试→重启后恢复）；④ **B4 主动心跳**——客户端 run spawn 心跳定时器；服务端 handle_client select 合并心跳周期+死连接检测（连续3周期无数据判死）；heartbeat_secs 此前从未使用；⑤ **F2 指标一致性**——`register_specific` 也必须计入 active_sessions（否则服务端会话 remove 时 fetch_sub 下溢成负数）；⑥ **F4/F5 会话上限**——allocate 加 MAX_SESSIONS-1 上限，ID 用 u32%256 显式 1..=255（原 id&0xFF 在 256 时有 0 号 bug）；⑦ **CLI -v 改 Option<u8>**（区分未指定与显式 -v 2，兑现 CLI>配置优先级）；⑧ **verify_password 修复**（不匹配应 Ok(false) 非 Err）。测试 19→26（dispatch 新增 7 事件型测试），release 零警告。涉及文件广泛（dispatch/listener/client mod/proxy/socks5/forward/cli/main/auth），详见 CHANGELOG 2026-08-19 12:00 条目。
- [2026-08-19 12:00] **事件型会话通道注意**：TunnelSession 提供 `recv()`（返回 Option<Vec<u8>>，Fin/Close→None，兼容旧调用）与 `recv_event()`（返回 Option<SessionEvent>，半关闭场景用）。TCP 转发必须用 recv_event 实现半关闭传播；UDP 无连接语义用 recv 即可（Fin/Close 即结束）。**测试环境变量启动的进程，pgrep -f 匹配不到 env 前缀**——验证断连时用 `ps -eo pid,args` 看实际进程再 kill。- [2026-08-19 12:35] **第二轮审查发现待修（S 级四项，修复前牢记）**：① `SrtConnection::close()` 发空 Vec 但 `run_send_loop` 不检查空消息不退出 -> socket 永不关闭（正确做法：close 直接 srt_close 让收发线程自然退出，eid 由接收线程释放；且 listener 认证失败 close+Drop 会双重 release epoll）；② SOCKS5 **监听失败**（非隧道断开）时 client::run 卡死在 `recv_task.await` 永不重连；③ 服务端 authenticate 等 RESPONSE 循环丢弃认证窗口内到达的 Open/Data 帧（accept 后固定 300ms+认证 RTT，客户端首个请求正好落入）且客户端转发无看门狗 -> 会话 ID 泄漏；④ 重连计数 attempt 成功后不清零，累计达 max_retries 进程退出。另：客户端 UDP ASSOCIATE 无 TCP 断开感知泄漏；UDP 目标域名/IPv6 被丢（0.0.0.0 占位）；服务端 socks5_users 是死配置（多用户认证从未实现）；Open 冲突时 remove(sid) 踢的是现有会话；rx_bytes 只在 recv() 计数（TCP 全走 recv_event 不计数）。详见 CHANGELOG 12:35 条目。
- [2026-08-19 15:00] **第二轮审查全部修复完成（S1-S6/H1-H5/M1-M8/L 级），修复中追加 2 个 S 级发现**：
  - **S5 断线状态值错误（历史 CPU 79% 卡死真凶）**：`srt_getsockstate` 返回 `SRTS_BROKEN=6/SRTS_CLOSED=8`（srt.h:159 枚举），旧代码判 `2||3`（实为 OPENED/LISTENING 健康态）-> 断线后收发线程永不退出+100µs 忙等。**判断断线必须用 `bindings::srt_state_unavailable(state)`（state>=6），禁止硬编码魔法数字**。
  - **S6 退出段错误（exit 139，gdb 定位 CRcvQueue::worker）**：libsrt 静态析构停 GC 线程与仍在跑的收发线程竞态。修复三件套：全局 `srt_global_init()`（Once+atexit 注册 srt_cleanup）；close() 保存并 join 线程 JoinHandle；main 手工建 runtime（失败走 EXIT_CODE 原子传递，runtime Drop 级联清理后才 exit）。**新增连接/退出路径改动时保持这三件套不破坏**。
  - S1 关闭语义：closed 是 AtomicBool CAS；send_tx 是 `Mutex<Option<Sender>>`（close 锁内 take+drop）；eid 归接收线程唯一释放。**不要再往 close() 加 srt_epoll_release/srt_close 以外的清理**（幂等由 CAS 保证）。
  - S3 认证回放：listener 的 `dispatch_one_frame` 是主循环与认证回放共用的唯一分发路径（改分发逻辑只改这一处）；两端断链时 `registry.close_all()` drop 全部会话通道 Sender 让转发任务 recv 得 None 退出。
  - H2 关键：服务端 UDP 转发是 **IPv4+IPv6 双栈双 socket**（`0.0.0.0:0` 是 IPv4-only，v6 目标必败）；地址头用 `encode_udp_addr_header_host`（host 字符串直传）。
  - 测试 25 个全过、release 零警告；端到端 TCP/UDP(4类)/断线重连 4 轮/退出码全部验证。测试进程清理：`pkill -f "target/release/srt-vpn"`。