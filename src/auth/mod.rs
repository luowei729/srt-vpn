//! auth/mod.rs — 认证模块
//!
//! 设计决策（Q4 + Q11，2026-08-20 更新）：
//! - SRT passphrase 原生加密（链路级，由新内核 quic/crypto.rs 承担）
//! - 连接认证：SRT 特征握手认证（srt_shell/auth.rs，防主动探测）
//! （旧双 HMAC 挑战-应答 + streamid 令牌已按重构共识移除）
//! - SOCKS5 用户认证（argon2 哈希存储，本文档保留）

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
/// 返回 Ok(true)=匹配 / Ok(false)=不匹配 / Err=哈希格式解析失败等错误
/// （P1 后半段接入 SOCKS5 多用户认证时启用）
/// 2026-08-19 审查修复：原实现 .map_err 链混乱，校验不匹配被误包装成 Err(false 字符串)。
#[allow(dead_code)]
pub fn verify_password(plain: &str, hash: &str) -> Result<bool, String> {
    let parsed = PasswordHash::new(hash).map_err(|e| format!("解析哈希失败: {e}"))?;
    // Argon2 校验：Ok=匹配，Err(PasswordError)=不匹配（这是预期结果，不是系统错误）
    match Argon2::default().verify_password(plain.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false), // 密码不匹配 → 返回 Ok(false)，由调用方决定是否拒绝
    }
}
