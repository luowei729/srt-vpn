//! auth/challenge.rs — 双 HMAC 挑战-应答认证
//!
//! 设计决策（Q11）：
//! - 服务器在握手后下发随机 nonce（CHALLENGE 消息）
//! - 客户端应答 = HMAC-SHA256(passphrase, nonce + 时间戳)
//! - 服务器校验应答 + 时间窗 30s（防重放）
//! - 认证失败：P1 断开连接 + 日志告警（P2 加黑名单/限频）

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 认证时间窗（秒）：应答中的时间戳必须在 [now-30s, now+30s] 内
pub const AUTH_TIME_WINDOW_SECS: i64 = 30;

/// 生成随机 nonce（服务器端 CHALLENGE 用）
/// 16 字节随机数，hex 编码传输
pub fn generate_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// 计算挑战-应答 HMAC（客户端用）
/// 应答 = HMAC-SHA256(passphrase, nonce_bytes + timestamp_le_bytes)
/// 时间戳为 Unix 秒（LE 8 字节），服务器端校验时间窗
pub fn compute_response(passphrase: &str, nonce: &str, timestamp: i64) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(passphrase.as_bytes())
        .expect("HMAC 初始化失败");
    // nonce 十六进制解码为原始字节（服务器下发的是 hex）
    if let Ok(nonce_bytes) = hex::decode(nonce) {
        mac.update(&nonce_bytes);
    } else {
        // nonce 非法时退化为按字符串更新（防御性编码，正常不会走到）
        mac.update(nonce.as_bytes());
    }
    mac.update(&timestamp.to_le_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// 校验挑战-应答（服务器端）
/// 1. 时间窗校验：|now - timestamp| <= 30s（防重放）
/// 2. HMAC 恒定时间比较
pub fn verify_response(passphrase: &str, nonce: &str, timestamp: i64, response: &str) -> Result<bool, String> {
    // 时间窗校验（防重放：过期或未来的应答都拒绝）
    let now = now_unix_secs();
    if (now - timestamp).abs() > AUTH_TIME_WINDOW_SECS {
        return Ok(false); // 时间窗外的应答直接拒绝
    }
    // 重算期望应答并恒定时间比较
    let expected = compute_response(passphrase, nonce, timestamp);
    let expected_bytes = expected.as_bytes();
    let resp_bytes = response.as_bytes();
    if expected_bytes.len() != resp_bytes.len() {
        return Ok(false);
    }
    let mut diff = 0u8;
    for (x, y) in expected_bytes.iter().zip(resp_bytes.iter()) {
        diff |= x ^ y;
    }
    Ok(diff == 0)
}

/// 当前 Unix 时间戳（秒）
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 生成当前时间戳（客户端 RESPONSE 用）
/// （P1 后半段客户端接入挑战-应答时启用）
#[allow(dead_code)]
pub fn current_timestamp() -> i64 {
    now_unix_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_response_roundtrip() {
        // 正常流程：客户端算应答 → 服务器校验通过
        let passphrase = "test-passphrase-123";
        let nonce = generate_nonce();
        let ts = current_timestamp();
        let resp = compute_response(passphrase, &nonce, ts);
        let ok = verify_response(passphrase, &nonce, ts, &resp).unwrap();
        assert!(ok, "正确应答应通过校验");
    }

    #[test]
    fn test_challenge_response_wrong_key() {
        // 错误 passphrase：校验失败
        let nonce = generate_nonce();
        let ts = current_timestamp();
        let resp = compute_response("wrong-passphrase", &nonce, ts);
        let ok = verify_response("right-passphrase", &nonce, ts, &resp).unwrap();
        assert!(!ok, "错误密钥不应通过校验");
    }

    #[test]
    fn test_challenge_response_replay() {
        // 时间窗外（30s 前）：重放攻击拒绝
        let passphrase = "test-passphrase-123";
        let nonce = generate_nonce();
        let old_ts = current_timestamp() - 60; // 60 秒前
        let resp = compute_response(passphrase, &nonce, old_ts);
        let ok = verify_response(passphrase, &nonce, old_ts, &resp).unwrap();
        assert!(!ok, "时间窗外的应答应被拒绝");
    }
}
