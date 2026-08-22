//! config.rs — 配置加载
//!
//! 设计决策（Q6）：统一 JSON 语法，文件名保持 server.conf / client.json
//! - 同一份 schema，mode 字段区分角色（server / client）
//! - serde 反序列化，缺省字段用默认值
//! - CLI 参数（-m、--socks5-*）优先级高于配置文件

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::cli::UdpMode;

/// 运行模式（配置文件 mode 字段）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// 服务端（监听 + 多客户端 + 直连转发）
    Server,
    /// 客户端（SOCKS5 入口 + 隧道）
    Client,
}

/// 全局配置（server.conf / client.json 统一 schema）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 运行模式：server / client（必填）
    pub mode: Mode,

    // ===== 通用字段 =====
    /// SRT passphrase（原生加密 + 挑战-应答密钥派生，必填）
    pub passphrase: String,
    /// 加密强度：aes-128（默认）/ aes-192 / aes-256
    #[serde(default = "default_crypto")]
    pub crypto: String,
    /// 指标 HTTP 端口（仅监听回环，默认关闭）
    #[serde(default)]
    pub metrics_port: Option<u16>,
    /// 日志级别覆盖（0-4）
    #[serde(default)]
    pub log_level: Option<u8>,

    // ===== 服务端字段 =====
    /// 监听地址（服务端必填，如 0.0.0.0:9000）
    #[serde(default)]
    pub listen: Option<String>,
    /// UDP 模式：reliable（默认）/ best-effort（-m 可覆盖）
    #[serde(default = "default_udp_mode")]
    pub udp_mode: UdpMode,
    /// 最大并发客户端数（默认 32）
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,
    /// SOCKS5 用户表（服务端认证客户端连接用，多用户哈希存储）
    #[serde(default)]
    pub socks5_users: Vec<Socks5User>,

    // ===== 客户端字段 =====
    /// 服务器地址（客户端必填，如 vpn.example.com:9000）
    #[serde(default)]
    pub server: Option<String>,
    /// streamid 令牌（客户端，默认内置格式）
    #[serde(default)]
    pub streamid: Option<String>,
    /// SOCKS5 入口配置（客户端）
    #[serde(default)]
    pub socks5: Option<Socks5Config>,
    /// 自动重连配置（客户端）
    #[serde(default)]
    pub reconnect: Option<ReconnectConfig>,
    /// 心跳间隔秒数（默认 5）
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,
}

/// SOCKS5 用户条目（服务端配置，用于认证客户端 SOCKS5 连接）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5User {
    /// 用户名
    pub username: String,
    /// 密码哈希（argon2 格式，如 $argon2id$v=19$...）
    pub password_hash: String,
}

/// 客户端 SOCKS5 入口配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    /// 监听地址（默认 127.0.0.1:1080，仅回环安全）
    #[serde(default = "default_socks5_listen")]
    pub listen: String,
    /// 用户名（本地认证，可空；单用户模式）
    #[serde(default)]
    pub username: Option<String>,
    /// 密码（本地认证，可空；单用户模式）
    #[serde(default)]
    pub password: Option<String>,
    /// 多用户表（H3 2026-08-19：多用户 argon2 认证，优先生效于单用户）
    /// 条目：{username, password_hash}（password_hash 为 argon2 PHC 格式）
    #[serde(default)]
    pub users: Vec<crate::client::socks5::Socks5UserEntry>,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            listen: default_socks5_listen(),
            username: None,
            password: None,
            users: Vec::new(),
        }
    }
}

impl Socks5Config {
    /// 是否配置了任何认证方式（单用户或用户表）
    ///
    /// 2026-08-19 审查修复：SOCKS5 握手根据此值决定是否接受"无认证"方法。
    /// 配置了认证时必须走 0x02 用户名密码认证，禁止 0x00 绕过。
    pub fn has_auth(&self) -> bool {
        self.username.is_some() || !self.users.is_empty()
    }
}

/// 客户端自动重连配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectConfig {
    /// 重连间隔秒数（默认 5）
    #[serde(default = "default_reconnect_interval")]
    pub interval_secs: u64,
    /// 最大重试次数（默认 10，-1 无限）
    #[serde(default = "default_reconnect_max")]
    pub max_retries: i64,
}

// ===== 通用辅助 =====

/// 加密强度字符串 -> pbkeylen 字节数（16/24/32 = aes-128/192/256）
/// L 级修复（2026-08-19）：统一到 config.rs（此前 client/mod.rs 与
/// server/mod.rs 各有一份重复实现，两处维护易分叉）
pub fn crypto_to_pbkeylen(crypto: &str) -> i32 {
    match crypto {
        "aes-192" => 24,
        "aes-256" => 32,
        _ => 16, // aes-128（默认，未知值回退）
    }
}

// ===== 默认值函数 =====

fn default_crypto() -> String {
    "aes-128".to_string()
}

fn default_udp_mode() -> UdpMode {
    UdpMode::Reliable
}

fn default_max_clients() -> usize {
    32
}

fn default_socks5_listen() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_reconnect_interval() -> u64 {
    5
}

fn default_reconnect_max() -> i64 {
    10
}

fn default_heartbeat() -> u64 {
    5
}

// ===== 环境变量配置辅助函数（Docker -e 场景） =====

/// 解析 SRT_MODE 环境变量（必填）
fn parse_env_mode() -> Result<Mode, String> {
    let m = std::env::var("SRT_MODE")
        .map_err(|_| "环境变量 SRT_MODE 缺失（server / client）".to_string())?;
    match m.as_str() {
        "server" => Ok(Mode::Server),
        "client" => Ok(Mode::Client),
        other => Err(format!("SRT_MODE 无效 '{other}'（可选：server / client）")),
    }
}

/// 解析可选的 u16 环境变量（端口），未设置返回 Ok(None)
fn parse_env_opt_u16(name: &str) -> Result<Option<u16>, String> {
    match std::env::var(name) {
        Ok(v) => v
            .parse::<u16>()
            .map(Some)
            .map_err(|_| format!("{name} 不是有效端口号")),
        Err(_) => Ok(None),
    }
}

/// 解析可选的 u8 环境变量（日志级别 0-4），未设置返回 Ok(None)
fn parse_env_opt_u8(name: &str) -> Result<Option<u8>, String> {
    match std::env::var(name) {
        Ok(v) => v
            .parse::<u8>()
            .map(Some)
            .map_err(|_| format!("{name} 不是有效数字")),
        Err(_) => Ok(None),
    }
}

/// 从环境变量构建服务端 SOCKS5 用户表
/// 格式：SRT_SOCKS5_USERS="user1:pass1,user2:pass2"（逗号分隔，明文密码转 argon2）
fn parse_env_socks5_users() -> Result<Vec<Socks5User>, String> {
    let raw = match std::env::var("SRT_SOCKS5_USERS") {
        Ok(v) => v,
        Err(_) => return Ok(Vec::new()),
    };
    let mut users = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (u, p) = entry
            .split_once(':')
            .ok_or_else(|| format!("SRT_SOCKS5_USERS 条目 '{entry}' 格式应为 user:pass"))?;
        // 明文密码转 argon2 哈希存储（与 CLI --socks5-users 一致）
        let hash = crate::auth::hash_password(p)
            .map_err(|e| format!("SRT_SOCKS5_USERS 用户 '{u}' 哈希失败: {e}"))?;
        users.push(Socks5User {
            username: u.trim().to_string(),
            password_hash: hash,
        });
    }
    Ok(users)
}

/// 从环境变量构建客户端自动重连配置（未设置 SRT_RECONNECT_* 返回 None）
fn build_reconnect_from_env() -> Result<Option<ReconnectConfig>, String> {
    let interval = std::env::var("SRT_RECONNECT_INTERVAL")
        .ok()
        .map(|s| s.parse::<u64>().map_err(|_| "SRT_RECONNECT_INTERVAL 不是有效数字".to_string()))
        .transpose()?;
    let max = std::env::var("SRT_RECONNECT_MAX")
        .ok()
        .map(|s| s.parse::<i64>().map_err(|_| "SRT_RECONNECT_MAX 不是有效数字".to_string()))
        .transpose()?;
    if interval.is_some() || max.is_some() {
        Ok(Some(ReconnectConfig {
            interval_secs: interval.unwrap_or_else(default_reconnect_interval),
            max_retries: max.unwrap_or_else(default_reconnect_max),
        }))
    } else {
        Ok(None)
    }
}

/// 从环境变量构建客户端 SOCKS5 配置（未设置任何 SRT_SOCKS5_* 返回 None）
fn build_socks5_from_env() -> Result<Option<Socks5Config>, String> {
    let listen = std::env::var("SRT_SOCKS5_LISTEN").unwrap_or_else(|_| default_socks5_listen());
    let username = std::env::var("SRT_SOCKS5_USER").ok();
    let password = std::env::var("SRT_SOCKS5_PASS").ok();
    // H3：多用户表（与单用户并存；users 非空时优先校验）
    let users = parse_env_socks5_users()?.into_iter().map(|u| crate::client::socks5::Socks5UserEntry {
        username: u.username,
        password_hash: u.password_hash,
    }).collect::<Vec<_>>();
    // 只要设置了任一 SRT_SOCKS5_* 就返回 Some（否则 None=用默认/文件值）
    let any_set = std::env::var("SRT_SOCKS5_LISTEN").is_ok()
        || username.is_some()
        || password.is_some()
        || !users.is_empty();
    if any_set {
        Ok(Some(Socks5Config {
            listen,
            username,
            password,
            users,
        }))
    } else {
        Ok(None)
    }
}

impl Config {
    /// 从文件加载配置
    pub fn load(path: &str) -> Result<Self, String> {
        let p = Path::new(path);
        let content = std::fs::read_to_string(p)
            .map_err(|e| format!("读取配置文件 {path} 失败: {e}"))?;
        let cfg: Config = serde_json::from_str(&content)
            .map_err(|e| format!("解析配置文件 {path} 失败: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// 从环境变量构建配置（Docker -e 场景，无配置文件时使用）
    ///
    /// 环境变量（前缀 SRT_，与配置字段一一对应）：
    /// - SRT_MODE / SRT_PASSPHRASE：必填（mode + passphrase）
    /// - SRT_CRYPTO / SRT_METRICS_PORT：可选（crypto / metrics_port）
    /// - 服务端：SRT_LISTEN（必填）/ SRT_UDP_MODE / SRT_MAX_CLIENTS
    /// - 客户端：SRT_SERVER（必填）/ SRT_SOCKS5_LISTEN / SRT_SOCKS5_USER /
    ///   SRT_SOCKS5_PASS / SRT_HEARTBEAT_SECS
    ///
    /// 解析失败/必填缺失返回 Err。非 SRT_ 前缀变量忽略。
    pub fn from_env() -> Result<Self, String> {
        let cfg = Config {
            mode: parse_env_mode()?,
            passphrase: std::env::var("SRT_PASSPHRASE")
                .map_err(|_| "环境变量 SRT_PASSPHRASE 缺失（SRT 加密密钥，两端必须一致）".to_string())?,
            crypto: std::env::var("SRT_CRYPTO").unwrap_or_else(|_| default_crypto()),
            metrics_port: parse_env_opt_u16("SRT_METRICS_PORT")?,
            log_level: parse_env_opt_u8("SRT_LOG_LEVEL")?,
            listen: std::env::var("SRT_LISTEN").ok(),
            udp_mode: std::env::var("SRT_UDP_MODE")
                .ok()
                .map(|s| UdpMode::parse_str(&s).map_err(|e| e.to_string()))
                .transpose()?
                .unwrap_or_else(default_udp_mode),
            max_clients: std::env::var("SRT_MAX_CLIENTS")
                .ok()
                .map(|s| s.parse::<usize>().map_err(|_| "SRT_MAX_CLIENTS 不是有效数字".to_string()))
                .transpose()?
                .unwrap_or_else(default_max_clients),
            socks5_users: parse_env_socks5_users()?,
            server: std::env::var("SRT_SERVER").ok(),
            streamid: std::env::var("SRT_STREAMID").ok(),
            socks5: build_socks5_from_env()?,
            reconnect: build_reconnect_from_env()?,
            heartbeat_secs: std::env::var("SRT_HEARTBEAT_SECS")
                .ok()
                .map(|s| s.parse::<u64>().map_err(|_| "SRT_HEARTBEAT_SECS 不是有效数字".to_string()))
                .transpose()?
                .unwrap_or_else(default_heartbeat),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// 应用环境变量覆盖（优先级：环境变量 > 配置文件）
    ///
    /// 用于已有配置文件时补充环境变量覆盖（Docker 场景：基础配置在文件，
    /// 需要临时改的参数用 -e 传入，无需重写配置）。
    pub fn apply_env(&mut self) {
        if let Ok(m) = parse_env_mode() {
            self.mode = m;
        }
        if let Ok(p) = std::env::var("SRT_PASSPHRASE") {
            self.passphrase = p;
        }
        if let Ok(c) = std::env::var("SRT_CRYPTO") {
            self.crypto = c;
        }
        if let Ok(mp) = parse_env_opt_u16("SRT_METRICS_PORT") {
            self.metrics_port = mp;
        }
        if let Ok(l) = std::env::var("SRT_LISTEN") {
            self.listen = Some(l);
        }
        if let Ok(u) = std::env::var("SRT_UDP_MODE") {
            if let Ok(udp) = UdpMode::parse_str(&u) {
                self.udp_mode = udp;
            }
        }
        if let Ok(mc) = std::env::var("SRT_MAX_CLIENTS") {
            if let Ok(v) = mc.parse::<usize>() {
                self.max_clients = v;
            }
        }
        if let Ok(ll) = parse_env_opt_u8("SRT_LOG_LEVEL") {
            self.log_level = ll;
        }
        if let Ok(users) = parse_env_socks5_users() {
            if !users.is_empty() {
                self.socks5_users = users;
            }
        }
        if let Ok(s) = std::env::var("SRT_SERVER") {
            self.server = Some(s);
        }
        if let Ok(sid) = std::env::var("SRT_STREAMID") {
            self.streamid = Some(sid);
        }
        if let Ok(rc) = build_reconnect_from_env() {
            if rc.is_some() {
                self.reconnect = rc;
            }
        }
        if let Ok(listen) = std::env::var("SRT_SOCKS5_LISTEN") {
            match &mut self.socks5 {
                Some(s5) => s5.listen = listen,
                None => self.socks5 = Some(Socks5Config {
                    listen,
                    username: None,
                    password: None,
                    users: Vec::new(),
                }),
            }
        }
        let user = std::env::var("SRT_SOCKS5_USER").ok();
        let pass = std::env::var("SRT_SOCKS5_PASS").ok();
        if user.is_some() || pass.is_some() {
            match &mut self.socks5 {
                Some(s5) => {
                    if let Some(u) = user { s5.username = Some(u); }
                    if let Some(p) = pass { s5.password = Some(p); }
                }
                None => {
                    self.socks5 = Some(Socks5Config {
                        listen: default_socks5_listen(),
                        username: user,
                        password: pass,
                        users: Vec::new(),
                    });
                }
            }
        }
        // H3：环境变量多用户表覆盖（SRT_SOCKS5_USERS 转入客户端 SOCKS5 入口用户表）
        if let Ok(users) = parse_env_socks5_users() {
            if !users.is_empty() {
                let entries = users.into_iter().map(|u| crate::client::socks5::Socks5UserEntry {
                    username: u.username,
                    password_hash: u.password_hash,
                }).collect::<Vec<_>>();
                match &mut self.socks5 {
                    Some(s5) => s5.users = entries,
                    None => self.socks5 = Some(Socks5Config {
                        listen: default_socks5_listen(),
                        username: None,
                        password: None,
                        users: entries,
                    }),
                }
            }
        }
        if let Ok(h) = std::env::var("SRT_HEARTBEAT_SECS") {
            if let Ok(v) = h.parse::<u64>() {
                self.heartbeat_secs = v;
            }
        }
    }

    /// 校验配置合法性（必填字段 + 取值范围）
    pub fn validate(&self) -> Result<(), String> {
        // passphrase 必填（SRT 原生加密 + 挑战-应答都需要）
        if self.passphrase.len() < 10 || self.passphrase.len() > 79 {
            return Err("passphrase 长度必须为 10-79 字符（SRT 协议要求）".to_string());
        }
        // M6 修复（2026-08-19）：max_clients 必须至少为 1。
        // 旧实现 0 可通过校验 -> 服务端永久拒绝所有连接且无限循环告警（无法提供服务）。
        if self.max_clients < 1 {
            return Err("max_clients 必须至少为 1".to_string());
        }
        // 加密强度校验
        match self.crypto.as_str() {
            "aes-128" | "aes-192" | "aes-256" => {}
            other => return Err(format!("无效的加密强度 '{other}'（可选：aes-128/aes-192/aes-256）")),
        }
        // 按模式校验必填字段
        match self.mode {
            Mode::Server => {
                if self.listen.is_none() {
                    return Err("服务端配置缺少 listen 字段（如 0.0.0.0:9000）".to_string());
                }
            }
            Mode::Client => {
                if self.server.is_none() {
                    return Err("客户端配置缺少 server 字段（如 vpn.example.com:9000）".to_string());
                }
            }
        }
        // SOCKS5 用户校验（如果配置了）
        for u in &self.socks5_users {
            if u.username.is_empty() {
                return Err("socks5_users 存在空用户名".to_string());
            }
            if !u.password_hash.starts_with("$argon2") {
                return Err(format!(
                    "用户 '{}' 的 password_hash 不是 argon2 格式（应以 $argon2 开头）",
                    u.username
                ));
            }
        }
        Ok(())
    }

    /// 应用 CLI 参数覆盖（优先级：CLI > 环境变量 > 配置文件）
    pub fn apply_cli(&mut self, args: &crate::cli::Args) {
        // --socks5-listen 覆盖客户端 SOCKS5 监听地址
        if let Some(listen) = &args.socks5_listen {
            match &mut self.socks5 {
                Some(s5) => s5.listen = listen.clone(),
                None => {
                    self.socks5 = Some(crate::config::Socks5Config {
                        listen: listen.clone(),
                        username: None,
                        password: None,
                        users: Vec::new(),
                    });
                }
            }
        }
        // --socks5-user / --socks5-pass 覆盖客户端 SOCKS5 凭据
        let (user, pass) = (args.socks5_user.clone(), args.socks5_pass.clone());
        if user.is_some() || pass.is_some() {
            match &mut self.socks5 {
                Some(s5) => {
                    if let Some(u) = user {
                        s5.username = Some(u);
                    }
                    if let Some(p) = pass {
                        s5.password = Some(p);
                    }
                }
                None => {
                    self.socks5 = Some(crate::config::Socks5Config {
                        listen: default_socks5_listen(),
                        username: user,
                        password: pass,
                        users: Vec::new(),
                    });
                }
            }
        }
        // --socks5-users 追加多用户（格式 user:pass，明文转 argon2，测试用；H3）
        for entry in &args.socks5_users {
            if let Some((u, p)) = entry.split_once(':') {
                // 测试用途：明文密码转 argon2 哈希存储
                if let Ok(hash) = crate::auth::hash_password(p) {
                    let entry = crate::client::socks5::Socks5UserEntry {
                        username: u.to_string(),
                        password_hash: hash,
                    };
                    // 写入客户端 SOCKS5 入口用户表（H3：多用户认证实际消费方）
                    match &mut self.socks5 {
                        Some(s5) => s5.users.push(entry),
                        None => {
                            self.socks5 = Some(crate::config::Socks5Config {
                                listen: default_socks5_listen(),
                                username: None,
                                password: None,
                                users: vec![entry],
                            });
                        }
                    }
                }
            }
        }
    }
}
