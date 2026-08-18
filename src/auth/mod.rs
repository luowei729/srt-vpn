//! auth/mod.rs — 认证模块
//!
//! 设计决策（Q4 + Q11）：
//! - SRT passphrase 原生加密（链路级，aes-128/192/256）
//! - streamid 静态令牌（第一道门，HMAC-SHA256(passphrase, 盐) 派生）
//! - 首条消息双 HMAC 挑战-应答（第二道门，nonce + 30s 时间窗防重放）
//! - SOCKS5 用户认证（argon2 哈希存储）

pub mod challenge;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// 对明文密码做 argon2id 哈希（SOCKS5 用户密码存储用）
/// 返回标准 PHC 格式字符串（$argon2id$v=19$...），可直接存配置
pub fn hash_password(plain: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("argon2 哈希失败: {e}"))
}

/// 校验明文密码是否匹配 argon2 哈希
/// （P1 后半段接入 SOCKS5 多用户认证时启用）
#[allow(dead_code)]
pub fn verify_password(plain: &str, hash: &str) -> Result<bool, String> {
    let parsed = PasswordHash::new(hash).map_err(|e| format!("解析哈希失败: {e}"))?;
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .map(|_| true)
        .map_err(|_| false)
        .map_err(|e| e.to_string())
        .map(|v| v)
        .map_err(|e| format!("argon2 校验失败: {e}"))
}

/// 从 passphrase 派生 streamid 静态令牌
/// 设计：令牌 = HMAC-SHA256(passphrase, "srtvpn-token-salt" 固定盐)
/// 服务端存储 passphrase 即可验证令牌（无需额外配置）
pub fn derive_token(passphrase: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(passphrase.as_bytes())
        .expect("HMAC 初始化失败");
    mac.update(b"srtvpn-token-v1");
    hex::encode(mac.finalize().into_bytes())
}

/// 构建带令牌的 streamid（客户端用）
/// 格式：标准 SRT 直播格式 + k= 令牌参数（URL 安全）
/// 例：#!::r=live/srtvpn,m=video,k=<hex token>
pub fn build_streamid(passphrase: &str, resource: &str) -> String {
    let token = derive_token(passphrase);
    format!("#!::r={resource},m=video,k={token}")
}

/// 从 streamid 提取令牌参数（服务端用）
/// 返回 None 表示没有令牌（认证失败）
pub fn extract_token(streamid: &str) -> Option<String> {
    // streamid 格式：#!::r=...,m=...,k=<token>
    // 按逗号分割参数段，找 k= 前缀
    for part in streamid.split(',') {
        if let Some(rest) = part.strip_prefix("k=") {
            return Some(rest.to_string());
        }
    }
    None
}

/// 校验 streamid 令牌（服务端用，恒定时间比较防时序攻击）
pub fn verify_token(streamid: &str, passphrase: &str) -> bool {
    match extract_token(streamid) {
        Some(t) => {
            let expected = derive_token(passphrase);
            // 恒定时间比较（防时序侧信道）
            constant_time_eq(t.as_bytes(), expected.as_bytes())
        }
        None => false,
    }
}

/// 恒定时间字符串比较（防时序攻击）
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
