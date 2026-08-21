//! TUIC 认证模块（服务端验证）
//!
//! 设计原因：TUIC 认证机制是 UUID+password → TLS exporter 派生 32B token。
//! 客户端通过 QUIC uni-stream 发送 Authenticate 命令（含 UUID + token），
//! 服务端用相同的 UUID+password 派生 token 比对验证。
//!
//! token = TLS.ExportKeyingMaterial(label=UUID_string, context=password, length=32)
//! 两端用相同 UUID+password → 相同 token（TLS 会话密钥相同）

use std::collections::HashMap;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::transport::driver::{DriverRequest, DriverError};

/// 验证客户端发送的 TUIC 认证 token
///
/// # 参数
/// - `uuid`: 客户端 UUID
/// - `token`: 客户端发送的 32B token
/// - `users`: 用户表（UUID → password）
/// - `req_tx`: 驱动器请求通道（用于获取 TLS exporter 密钥材料）
///
/// # 返回
/// - `Ok(true)`: 认证成功
/// - `Ok(false)`: 认证失败（UUID 不存在或 token 不匹配）
/// - `Err`: 认证过程出错（如 TLS exporter 调用失败）
pub async fn verify_token(
    uuid: &Uuid,
    token: &[u8; 32],
    users: &HashMap<Uuid, String>,
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
) -> Result<bool, String> {
    // 1. 查找 UUID 对应的密码
    let password = match users.get(uuid) {
        Some(p) => p.clone(),
        None => {
            tracing::warn!(%uuid, "未知用户 UUID");
            return Ok(false);
        }
    };

    // 2. 用 TLS exporter 派生 token（label=UUID, context=password）
    let label = uuid.as_bytes().to_vec();
    let context = password.as_bytes().to_vec();
    tracing::debug!(%uuid, "服务端调用 TLS exporter 派生 token");
    let expected_token = match request_export_keying_material(req_tx, 32, label, context).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(%uuid, error = %e, "TLS exporter 调用失败");
            return Err(e);
        }
    };
    tracing::debug!(%uuid, "TLS exporter 成功，比对 token");

    // 3. 比对 token（常量时间比较防时序攻击）
    let expected = &expected_token[..32];
    if expected.len() != token.len() {
        return Ok(false);
    }

    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(token.iter()) {
        diff |= a ^ b;
    }

    Ok(diff == 0)
}

/// 请求 TLS exporter 密钥材料
async fn request_export_keying_material(
    req_tx: &mpsc::UnboundedSender<DriverRequest>,
    output_len: usize,
    label: Vec<u8>,
    context: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    req_tx
        .send(DriverRequest::ExportKeyingMaterial {
            output_len,
            label,
            context,
            reply: reply_tx,
        })
        .map_err(|_| "驱动器通道关闭".to_string())?;

    reply_rx
        .await
        .map_err(|_| "驱动器回复通道关闭".to_string())?
        .map_err(|e| format!("TLS exporter 错误: {}", e))
}
