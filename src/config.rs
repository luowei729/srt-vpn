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
    /// 用户名（本地认证，可空）
    #[serde(default)]
    pub username: Option<String>,
    /// 密码（本地认证，可空）
    #[serde(default)]
    pub password: Option<String>,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            listen: default_socks5_listen(),
            username: None,
            password: None,
        }
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

    /// 校验配置合法性（必填字段 + 取值范围）
    pub fn validate(&self) -> Result<(), String> {
        // passphrase 必填（SRT 原生加密 + 挑战-应答都需要）
        if self.passphrase.len() < 10 || self.passphrase.len() > 79 {
            return Err("passphrase 长度必须为 10-79 字符（SRT 协议要求）".to_string());
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

    /// 应用 CLI 参数覆盖（优先级：CLI > 配置）
    pub fn apply_cli(&mut self, args: &crate::cli::Args) {
        // -m 覆盖 udp_mode（仅服务端有意义）
        if let Some(m) = &args.udp_mode {
            match UdpMode::parse_str(m) {
                Ok(udp_mode) => self.udp_mode = udp_mode,
                Err(e) => {
                    tracing::warn!(error = %e, "忽略无效的 -m 参数");
                }
            }
        }
        // --socks5-listen 覆盖客户端 SOCKS5 监听地址
        if let Some(listen) = &args.socks5_listen {
            match &mut self.socks5 {
                Some(s5) => s5.listen = listen.clone(),
                None => {
                    self.socks5 = Some(crate::config::Socks5Config {
                        listen: listen.clone(),
                        username: None,
                        password: None,
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
                    });
                }
            }
        }
        // --socks5-users 追加服务端多用户（格式 user:pass，纯文本，测试用）
        for entry in &args.socks5_users {
            if let Some((u, p)) = entry.split_once(':') {
                // 测试用途：明文密码转 argon2 哈希存储
                if let Ok(hash) = crate::auth::hash_password(p) {
                    self.socks5_users.push(Socks5User {
                        username: u.to_string(),
                        password_hash: hash,
                    });
                }
            }
        }
    }
}
