//! 配置加载模块
//!
//! 设计原因：统一 JSON 配置格式，字段名遵循 TUIC 原生命名习惯。
//! 支持配置文件 + 环境变量覆盖（SRT_* 前缀）。
//! passwall 通过 util_srt-vpn.lua 生成 client.json，字段必须匹配此 schema。

use crate::cli::Mode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use uuid::Uuid;

/// 顶层配置结构
///
/// 客户端和服务端共用一份配置，通过 `mode` 字段区分。
/// 字段名遵循 TUIC 原生命名（uuid/password/server/socks5）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 运行模式：server / client
    pub mode: Mode,

    // === 通用字段（客户端+服务端共用）===
    /// SRT 握手密码短语（用于派生临时加密密钥，双阶段密钥派生阶段1）
    ///
    /// 客户端和服务端必须一致。不是 TUIC 认证密码（认证用 uuid+password）。
    pub passphrase: String,

    /// 日志级别：error/warn/info/debug/trace（默认 info）
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// 指标服务端口（0=禁用，默认 9090）
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    // === 客户端字段 ===
    /// 服务端地址（客户端模式必填，格式 host:port，支持域名）
    pub server: Option<String>,

    /// TUIC 认证 UUID（客户端模式必填）
    pub uuid: Option<Uuid>,

    /// TUIC 认证密码（客户端模式必填，与 uuid 配对）
    pub password: Option<String>,

    /// SOCKS5+HTTP 三合一代理监听地址（客户端模式必填，格式 ip:port）
    ///
    /// 同端口提供 SOCKS5 + HTTP + HTTPS 代理（首字节嗅探分流）。
    /// passwall 契约：不设独立 http 端口。
    pub socks5: Option<Socks5Config>,

    /// 心跳间隔秒数（默认 10s，TUIC 原版默认值）
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,

    /// 重连配置（客户端模式）
    #[serde(default)]
    pub reconnect: ReconnectConfig,

    // === 服务端字段 ===
    /// 服务端监听地址（服务端模式必填）
    pub listen: Option<String>,

    /// TUIC 用户表（服务端模式必填：UUID → 密码）
    ///
    /// 支持多用户，每用户独立 UUID+密码。
    /// passwall 侧可配多个节点或单节点多用户。
    #[serde(default)]
    pub users: Vec<UserConfig>,

    /// TLS 证书文件路径（服务端模式必填）
    ///
    /// quinn-proto 需要 TLS 证书做 QUIC 握手（虽然线路上被 AES 加密覆盖，
    /// 但 quinn-proto 内部仍需 TLS 证书驱动握手状态机）。
    pub cert: Option<String>,

    /// TLS 私钥文件路径（服务端模式必填）
    pub key: Option<String>,

    /// 最大客户端连接数（服务端模式，默认 32）
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,

    // === 已废弃字段（向后兼容，保留但不校验，见 CHANGELOG 2026-08-21）===
    /// @deprecated: pool_size（v0.4.0 已删连接池，单 QUIC 连接多路复用）
    #[serde(default)]
    pub pool_size: Option<usize>,
    /// @deprecated: crypto（v0.4.0 加密统一 AES-128-CTR 由 passphrase 派生）
    #[serde(default)]
    pub crypto: Option<String>,
    /// @deprecated: streamid（v0.4.0 静态令牌已删）
    #[serde(default)]
    pub streamid: Option<String>,

    // === 环境变量覆盖标记（内部使用，不从 JSON 读取）===
    #[serde(skip)]
    pub _env_overridden: bool,
}

/// SOCKS5+HTTP 代理配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    /// 监听地址（格式 ip:port，如 "127.0.0.1:1080"）
    pub listen: String,
    /// SOCKS5 认证用户名（null=无认证）
    #[serde(default)]
    pub username: Option<String>,
    /// SOCKS5 认证密码（null=无认证）
    #[serde(default)]
    pub password: Option<String>,
}

/// 重连配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectConfig {
    /// 重连间隔秒数（默认 5s）
    #[serde(default = "default_reconnect_interval")]
    pub interval_secs: u64,
    /// 最大重连次数（0=无限重连，默认 0）
    #[serde(default = "default_reconnect_max")]
    pub max_retries: u32,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_reconnect_interval(),
            max_retries: default_reconnect_max(),
        }
    }
}

/// TUIC 用户配置（服务端多用户）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// 用户 UUID（唯一标识）
    pub uuid: Uuid,
    /// 用户密码（明文，服务端启动时加载）
    pub password: String,
}

// === 默认值函数 ===

fn default_log_level() -> String {
    "info".to_string()
}
fn default_metrics_port() -> u16 {
    9090
}
fn default_heartbeat() -> u64 {
    10
}
fn default_max_clients() -> usize {
    32
}
fn default_reconnect_interval() -> u64 {
    5
}
fn default_reconnect_max() -> u32 {
    0
}

impl Config {
    /// 从 JSON 文件加载配置
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::FileRead(path.to_string(), e.to_string()))?;
        let mut config: Config = serde_json::from_str(&content)
            .map_err(|e| ConfigError::Parse(e.to_string()))?;

        // 应用环境变量覆盖（优先级：环境变量 > 配置文件 > 默认）
        config.apply_env();
        config.validate()?;
        Ok(config)
    }

    /// 从纯环境变量构建配置（不传 -c 时）
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Config {
            mode: Mode::Client, // 默认值，会被环境变量覆盖
            passphrase: String::new(),
            log_level: default_log_level(),
            metrics_port: default_metrics_port(),
            server: None,
            uuid: None,
            password: None,
            socks5: None,
            heartbeat_secs: default_heartbeat(),
            reconnect: ReconnectConfig::default(),
            listen: None,
            users: Vec::new(),
            cert: None,
            key: None,
            max_clients: default_max_clients(),
            pool_size: None,
            crypto: None,
            streamid: None,
            _env_overridden: false,
        };
        config.apply_env();
        config.validate()?;
        Ok(config)
    }

    /// 应用 SRT_* 环境变量覆盖配置
    ///
    /// 优先级：SRT_* 环境变量 > 配置文件值 > 默认值
    fn apply_env(&mut self) {
        // SRT_MODE: server / client
        if let Ok(mode) = std::env::var("SRT_MODE") {
            self.mode = match mode.to_lowercase().as_str() {
                "server" => Mode::Server,
                "client" => Mode::Client,
                _ => self.mode,
            };
            self._env_overridden = true;
        }

        // SRT_PASSPHRASE: SRT 握手密码短语
        if let Ok(v) = std::env::var("SRT_PASSPHRASE") {
            if !v.is_empty() {
                self.passphrase = v;
            }
        }

        // SRT_LOG_LEVEL: 日志级别
        if let Ok(v) = std::env::var("SRT_LOG_LEVEL") {
            if !v.is_empty() {
                self.log_level = v;
            }
        }

        // SRT_METRICS_PORT: 指标端口
        if let Ok(v) = std::env::var("SRT_METRICS_PORT") {
            if let Ok(port) = v.parse::<u16>() {
                self.metrics_port = port;
            }
        }

        // SRT_SERVER: 服务端地址（客户端模式）
        if let Ok(v) = std::env::var("SRT_SERVER") {
            if !v.is_empty() {
                self.server = Some(v);
            }
        }

        // SRT_UUID: TUIC 认证 UUID（客户端模式）
        if let Ok(v) = std::env::var("SRT_UUID") {
            if let Ok(uuid) = v.parse::<Uuid>() {
                self.uuid = Some(uuid);
            }
        }

        // SRT_PASSWORD: TUIC 认证密码（客户端模式）
        if let Ok(v) = std::env::var("SRT_PASSWORD") {
            if !v.is_empty() {
                self.password = Some(v);
            }
        }

        // SRT_SOCKS5_LISTEN: SOCKS5+HTTP 监听地址（客户端模式）
        if let Ok(v) = std::env::var("SRT_SOCKS5_LISTEN") {
            if !v.is_empty() {
                self.socks5 = Some(Socks5Config {
                    listen: v,
                    username: std::env::var("SRT_SOCKS5_USER").ok().filter(|s| !s.is_empty()),
                    password: std::env::var("SRT_SOCKS5_PASS").ok().filter(|s| !s.is_empty()),
                });
            }
        }

        // SRT_HEARTBEAT_SECS: 心跳间隔
        if let Ok(v) = std::env::var("SRT_HEARTBEAT_SECS") {
            if let Ok(secs) = v.parse::<u64>() {
                self.heartbeat_secs = secs;
            }
        }

        // SRT_LISTEN: 服务端监听地址
        if let Ok(v) = std::env::var("SRT_LISTEN") {
            if !v.is_empty() {
                self.listen = Some(v);
            }
        }

        // SRT_SOCKS5_USERS: 多用户配置（服务端模式，格式 "uuid:password,uuid:password"）
        // 明文传入，服务端启动时加载
        if let Ok(v) = std::env::var("SRT_SOCKS5_USERS") {
            if !v.is_empty() {
                self.users = v
                    .split(',')
                    .filter_map(|entry| {
                        let parts: Vec<&str> = entry.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            let uuid = Uuid::parse_str(parts[0]).ok()?;
                            let password = parts[1].to_string();
                            Some(UserConfig { uuid, password })
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }

        // SRT_CERT / SRT_KEY: TLS 证书路径
        if let Ok(v) = std::env::var("SRT_CERT") {
            if !v.is_empty() {
                self.cert = Some(v);
            }
        }
        if let Ok(v) = std::env::var("SRT_KEY") {
            if !v.is_empty() {
                self.key = Some(v);
            }
        }

        // SRT_MAX_CLIENTS: 最大客户端连接数
        if let Ok(v) = std::env::var("SRT_MAX_CLIENTS") {
            if let Ok(n) = v.parse::<usize>() {
                self.max_clients = n;
            }
        }

        // SRT_RECONNECT_INTERVAL / SRT_RECONNECT_MAX: 重连配置
        if let Ok(v) = std::env::var("SRT_RECONNECT_INTERVAL") {
            if let Ok(secs) = v.parse::<u64>() {
                self.reconnect.interval_secs = secs;
            }
        }
        if let Ok(v) = std::env::var("SRT_RECONNECT_MAX") {
            if let Ok(n) = v.parse::<u32>() {
                self.reconnect.max_retries = n;
            }
        }

        // 已废弃：pool_size / crypto / streamid（v0.4.0 已删，保留兼容但忽略）
        if std::env::var("SRT_POOL_SIZE").is_ok() {
            tracing::warn!("SRT_POOL_SIZE 已废弃（v0.4.0 单 QUIC 连接多路复用，无连接池）");
        }
    }

    /// 校验配置完整性
    fn validate(&self) -> Result<(), ConfigError> {
        if self.passphrase.is_empty() {
            return Err(ConfigError::Validation("passphrase 不能为空".into()));
        }

        match self.mode {
            Mode::Client => {
                // 客户端必须有 server / uuid / password / socks5
                if self.server.is_none() {
                    return Err(ConfigError::Validation("客户端模式缺少 server".into()));
                }
                if self.uuid.is_none() {
                    return Err(ConfigError::Validation("客户端模式缺少 uuid".into()));
                }
                if self.password.is_none() {
                    return Err(ConfigError::Validation("客户端模式缺少 password".into()));
                }
                if self.socks5.is_none() {
                    return Err(ConfigError::Validation("客户端模式缺少 socks5.listen".into()));
                }
            }
            Mode::Server => {
                // 服务端必须有 listen / users / cert / key
                if self.listen.is_none() {
                    return Err(ConfigError::Validation("服务端模式缺少 listen".into()));
                }
                if self.users.is_empty() {
                    return Err(ConfigError::Validation("服务端模式缺少 users".into()));
                }
                if self.cert.is_none() {
                    return Err(ConfigError::Validation("服务端模式缺少 cert（TLS证书）".into()));
                }
                if self.key.is_none() {
                    return Err(ConfigError::Validation("服务端模式缺少 key（TLS私钥）".into()));
                }
            }
        }
        Ok(())
    }

    /// 解析服务端监听地址为 SocketAddr
    pub fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        let addr_str = self.listen.as_ref().ok_or_else(|| {
            ConfigError::Validation("服务端模式缺少 listen".into())
        })?;
        addr_str
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::Parse(format!("listen 地址解析失败: {}", e)))
    }

    /// 解析 SOCKS5 监听地址为 SocketAddr
    pub fn socks5_listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        let socks5 = self.socks5.as_ref().ok_or_else(|| {
            ConfigError::Validation("客户端模式缺少 socks5".into())
        })?;
        socks5
            .listen
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::Parse(format!("socks5.listen 地址解析失败: {}", e)))
    }

    /// 获取服务端用户表（UUID → 密码）
    pub fn user_map(&self) -> HashMap<Uuid, String> {
        self.users
            .iter()
            .map(|u| (u.uuid, u.password.clone()))
            .collect()
    }
}

/// 配置错误类型
#[derive(Debug)]
pub enum ConfigError {
    /// 文件读取失败
    FileRead(String, String),
    /// JSON 解析失败
    Parse(String),
    /// 配置校验失败
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::FileRead(path, e) => write!(f, "配置文件读取失败 {}: {}", path, e),
            ConfigError::Parse(e) => write!(f, "配置解析失败: {}", e),
            ConfigError::Validation(e) => write!(f, "配置校验失败: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}
