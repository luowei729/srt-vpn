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

/// 认证时间窗（秒）：应答中的时间戳必须在 [now-90s, now+90s] 内
/// 2026-08-20 从 30s 放宽到 90s：软路由/嵌入式设备时钟漂移常见（实测软路由
/// 偏差 51s 导致更新二进制后全体认证失败，且 NTP 走隧道断开时形成死循环
/// --时间纠不回隧道就永难重建）。放宽安全性分析：重放防护由 nonce 连接级
/// 一次性保证（每连接唯一 nonce，无法跨连接重放），时间窗只挡“过期应答”，
/// 90s 内重放同一应答也需携带同一 nonce 且连接未断，实际风险可控。
pub const AUTH_TIME_WINDOW_SECS: i64 = 90;

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
/// 1. 时间窗校验：|now - timestamp| <= AUTH_TIME_WINDOW_SECS（防重放）
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

/// 双路径应答校验（2026-08-20 对时握手核心，服务端用）
///
/// - `server_ts`：本连接 CHALLENGE 下发时携带的服务端时间戳
/// - `client_ts`：RESPONSE 里客户端声明的时间戳
///
/// 路径 A（新客户端，v0.2.2+）：客户端直接用 server_ts 计算 HMAC ->
///   按 server_ts 重算比对即可（与客户端本地时钟完全无关）。
///   防重放不降级：server_ts 在 HMAC 内（不可伪造），nonce 连接级一次性，
///   且要求 |now - server_ts| <= 窗口（陈旧 CHALLENGE 应答在窗口后失效）。
/// 路径 B（旧客户端）：应答按客户端本地时间计算 ->
///   走原 90s 窗口校验（兼容 <0.2.2 客户端，时钟漂移大时仍会失败但报明确偏差）。
///
/// 返回 (是否通过, 时钟偏差秒数[供诊断日志])。
pub fn verify_response_dual(
    passphrase: &str,
    nonce: &str,
    server_ts: i64,
    client_ts: i64,
    response: &str,
) -> Result<(bool, i64), String> {
    let now = now_unix_secs();
    // 路径 A：新客户端（应答按 server_ts 计算）
    if compute_response(passphrase, nonce, server_ts) == response {
        // 陈旧性校验：CHALLENGE 下发至今不得超过窗口（防抓包重放老应答）
        if (now - server_ts).abs() <= AUTH_TIME_WINDOW_SECS {
            return Ok((true, now - server_ts)); // 偏差=往返耗时（秒级）
        }
        return Ok((false, now - server_ts));
    }
    // 路径 B：旧客户端（应答按其本地时间计算），90s 窗口兜底
    let delta = now - client_ts; // 正=客户端慢，负=客户端快
    let ok = verify_response(passphrase, nonce, client_ts, response)?;
    Ok((ok, delta))
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
        // 时间窗外：重放攻击拒绝（2026-08-20 窗口 30s->90s，测试同步用 120s 前样本）
        let passphrase = "test-passphrase-123";
        let nonce = generate_nonce();
        let old_ts = current_timestamp() - 120; // 120 秒前（超出 90s 窗口）
        let resp = compute_response(passphrase, &nonce, old_ts);
        let ok = verify_response(passphrase, &nonce, old_ts, &resp).unwrap();
        assert!(!ok, "时间窗外的应答应被拒绝");
    }

    // ===== 2026-08-20 对时握手测试（verify_response_dual）=====

    #[test]
    fn test_dual_new_client_ignores_local_clock() {
        // 新客户端（v0.2.2+）：用服务端 ts 计算应答。
        // 关键验证：客户端本地时钟漂移 10 万秒（27+小时）也照样认证通过！
        let passphrase = "test-passphrase-123";
        let nonce = generate_nonce();
        let server_ts = current_timestamp();
        // 客户端应答按 server_ts 算（对时握手），RESPONSE 里的 timestamp 字段=server_ts
        let resp = compute_response(passphrase, &nonce, server_ts);
        // 本地时钟假设漂移巨大：client_ts 声明的时间偏差 10 万秒
        let client_ts = server_ts + 100_000;
        let (ok, _) = verify_response_dual(passphrase, &nonce, server_ts, client_ts, &resp).unwrap();
        assert!(ok, "对时握手：客户端本地时钟漂移 10 万秒也应认证通过");
    }

    #[test]
    fn test_dual_old_client_fallback() {
        // 旧客户端（<0.2.2）：应答按其本地时间算，走 90s 窗口路径。
        // 本地时钟正常（偏差 5s）-> 通过
        let passphrase = "test-passphrase-123";
        let nonce = generate_nonce();
        let server_ts = current_timestamp();
        let client_ts = current_timestamp() - 5; // 客户端慢 5s（窗口内）
        let resp = compute_response(passphrase, &nonce, client_ts);
        let (ok, delta) = verify_response_dual(passphrase, &nonce, server_ts, client_ts, &resp).unwrap();
        assert!(ok, "旧客户端时钟窗口内应通过");
        assert_eq!(delta, 5, "偏差诊断值应为 5s");
    }

    #[test]
    fn test_dual_old_client_clock_skew_rejected() {
        // 旧客户端时钟漂移超窗（快 100s）-> 拒绝（真实故障场景：软路由快 51s 在旧 30s 窗口下失败）
        let passphrase = "test-passphrase-123";
        let nonce = generate_nonce();
        let server_ts = current_timestamp();
        let client_ts = current_timestamp() + 100; // 客户端快 100s
        let resp = compute_response(passphrase, &nonce, client_ts);
        let (ok, delta) = verify_response_dual(passphrase, &nonce, server_ts, client_ts, &resp).unwrap();
        assert!(!ok, "旧客户端时钟超窗应拒绝");
        assert_eq!(delta, -100, "偏差方向：客户端快为负");
    }

    #[test]
    fn test_dual_stale_challenge_rejected() {
        // 对时握手的陈旧性校验：CHALLENGE 下发太久（超过窗口）的应答拒绝（防抓包重放）
        let passphrase = "test-passphrase-123";
        let nonce = generate_nonce();
        let server_ts = current_timestamp() - 200; // CHALLENGE 是 200s 前发的
        let resp = compute_response(passphrase, &nonce, server_ts);
        let (ok, _) = verify_response_dual(passphrase, &nonce, server_ts, server_ts, &resp).unwrap();
        assert!(!ok, "陈旧 CHALLENGE 应答应被拒绝（防重放）");
    }

    #[test]
    fn test_dual_wrong_passphrase() {
        // 错误密钥：两条路径都不通过
        let nonce = generate_nonce();
        let server_ts = current_timestamp();
        let resp = compute_response("wrong-passphrase-999", &nonce, server_ts);
        let (ok, _) = verify_response_dual("right-passphrase-123", &nonce, server_ts, server_ts, &resp).unwrap();
        assert!(!ok, "错误 passphrase 应拒绝");
    }
}
