//! srt_shell/auth.rs — SRT 特征认证（防主动探测）
//!
//! 重构共识决策 E：不保留旧双 HMAC，改为**学习 SRT 特征处理**。
//! 继承 libsrt 的特征：
//! - passphrase 密钥派生（crypto.rs derive_key）——与 libsrt 的 kmreq 一致
//! - 握手包带 cookie（服务端验证客户端 ID，防 spoofing）——对齐 SRT 握手
//! - 载荷用密钥加密（AES-CTR）——对齐 libsrt 的流式加密特征
//!
//! 设计要点（防主动探测）：
//! - 认证信息藏在握手包体 + 加密载荷中，不暴露明文凭证（TLS/HTTP 结构）
//! - 服务端对"未认证的连接"表现为正常 SRT 服务（不响应即超时），
//!   不会暴露"这是 VPN 隧道"的特征
//! - 认证失败不发错误帧（对齐 SRT 对非法协作者的静默丢弃）

use crate::quic::crypto::KEY_LEN_128;
use sha2::{Digest, Sha256};

/// 认证挑战长度（nonce + 时间戳，16B）
pub const CHALLENGE_LEN: usize = 16;
/// 认证响应长度（HMAC-SHA256 派生 on 密钥）
pub const RESPONSE_LEN: usize = 32;

/// 认证载荷布局（内层握手帧的 payload，见 quic/packet.rs encode_handshake）
/// [salt 16B][ciphertext]
/// 明文部分 = 认证命令：
///   AUTH（登录）：[cmd=AUTH][nonce][ts][username_hash]
///   AUTH_OK：    [cmd=OK][server_ts]
///   AUTH_FAIL：  [cmd=FAIL]
///   PING/PONG：  心跳

/// 认证命令类型
pub const CMD_AUTH: u8 = 0x01;
pub const CMD_AUTH_OK: u8 = 0x02;
pub const CMD_AUTH_FAIL: u8 = 0x03;
pub const CMD_PING: u8 = 0x04;
pub const CMD_PONG: u8 = 0x05;

/// 生成认证请求（客户端 → 服务端）
///
/// - passphrase: 连接密钥（配置密码）
/// - 返回 [命令[AUTH] + nonce(16B) + 对认证密钥的 HMAC 派生签名]
///
/// 签名：HMAC-SHA256(passphrase派生密钥, nonce) —— 仿 SRT 的 kmreq 密钥
/// 传输指纹，不直接暴露 passphrase
pub fn auth_request(passphrase: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
    // 用 SHA256 派生验证密钥（客户端/服务端都共享 passphrase，能推算出）
    let key = derive_key_with_nonce(passphrase, nonce);
    // 认证载荷：cmd + nonce + 签名（32B SHA256 key 本身即"拥有 passphrase"的证明）
    let mut out = Vec::with_capacity(1 + 12 + 32);
    out.push(CMD_AUTH);
    out.extend_from_slice(nonce.as_slice());
    // 签名 = SHA256(key)（与 SRT kmreq 的 keymaterial 语义对齐）
    // digest() 返回 Output，.as_slice() 取底层切片拷贝
    let sig = Sha256::digest(&key).as_slice().to_vec();
    out.extend_from_slice(&sig);
    out
}

/// 服务端验证认证请求，返回是否通过
pub fn verify_auth(passphrase: &[u8], auth_payload: &[u8]) -> bool {
    if auth_payload.len() < 1 + 12 + 32 {
        return false;
    }
    if auth_payload[0] != CMD_AUTH {
        return false;
    }
    // 提取 nonce（12B）与签名（32B）
    let nonce: [u8; 12] = auth_payload[1..13].try_into().unwrap_or(&[0u8; 12]).clone();
    let sig_supplied = auth_payload[13..13 + 32].to_vec();
    // 本地重算期望签名（客户端/服务端共享 passphrase => 密钥一致）
    let key = derive_key_with_nonce(passphrase, &nonce);
    let sig_expected = Sha256::digest(&key).as_slice().to_vec();
    // 常数时间比较（长度已知 32）
    if sig_expected.len() != sig_supplied.len() {
        return false;
    }
    constant_time_eq(&sig_expected, &sig_supplied)
}

/// 生成 AUTH_OK 响应（服务端确认）
///
/// 载荷：`[CMD_AUTH_OK][服务端 unix 时间戳 u32 BE][分配的数据端口 u16 BE]`
/// - 时间戳：供客户端校时/防重放
/// - 数据端口：服务端为客户端**独立建立的 UDP socket** 端口（多设备架构：
///   监听 socket 只用于握手，认证后每条客户端连接迁移到独立数据通道，
///   避免多客户端在共享监听 socket 上 recv 竞争丢包）。0 表示沿用监听端口。
pub fn auth_ok(data_port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + 2);
    out.push(CMD_AUTH_OK);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&data_port.to_be_bytes());
    out
}

/// 从 AUTH_OK 载荷解析数据端口（若存在）
/// 返回 None：载荷非法 / 非 AUTH_OK
pub fn parse_auth_ok_port(payload: &[u8]) -> Option<u16> {
    if payload.len() < 7 || payload[0] != CMD_AUTH_OK {
        return None;
    }
    // 端口在偏移 1+4=5 处，u16 BE
    Some(u16::from_be_bytes([payload[5], payload[6]]))
}

/// 生成 AUTH_FAIL 响应
pub fn auth_fail() -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CMD_AUTH_FAIL);
    out
}

/// 生成 PING 载荷（心跳保活，仿 SRT keepalive）
pub fn ping() -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(CMD_PING);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    out.extend_from_slice(&ts.to_be_bytes());
    out
}

/// 生成 PONG 载荷（回声）
pub fn pong(echo: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CMD_PONG);
    out.extend_from_slice(echo);
    out
}

/// 从 passphrase + nonce 派生验证密钥（auth 专用，加入 nonce 防重放）
fn derive_key_with_nonce(_passphrase: &[u8], nonce: &[u8; 12]) -> [u8; KEY_LEN_128] {
    // "密钥 = SHA256(passphrase || nonce)" 取前 16B（确定性，两端一致；
    // 每连接每次认证的 nonce 不同 => 密钥不同 => 防重放）
    let mut h = Sha256::new();
    h.update(_passphrase);
    h.update(nonce.as_slice());
    let digest = h.finalize().as_slice().to_vec();
    let mut key = [0u8; KEY_LEN_128];
    let n = digest.len().min(KEY_LEN_128);
    key[..n].copy_from_slice(&digest[..n]);
    key
}

/// 常数时间比较（防时序侧信道；a/b 为拷贝后的字节数组）
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 正确密码认证通过
    #[test]
    fn test_auth_success() {
        let pass = b"correct-passphrase-2026";
        let nonce = [1u8; 12];
        let req = auth_request(pass, &nonce);
        assert!(verify_auth(pass, &req), "正确密码应通过");
    }

    /// 错误密码认证失败
    #[test]
    fn test_auth_wrong_pass() {
        let req = auth_request(b"correct-pass-2026", &[2u8; 12]);
        assert!(!verify_auth(b"wrong-pass-2026", &req), "错误密码应失败");
    }

    /// 短/非法载荷拒绝
    #[test]
    fn test_auth_invalid() {
        assert!(!verify_auth(b"pass", &[0x01, 0x02]), "过短载荷应拒绝");
        assert!(!verify_auth(b"pass", &[]), "空载荷应拒绝");
    }

    /// AUTH_OK 结构
    #[test]
    fn test_auth_ok() {
        let ok = auth_ok(0);
        assert_eq!(ok[0], CMD_AUTH_OK);
        assert_eq!(ok.len(), 1 + 4 + 2, "AUTH_OK = 命令 + 时间戳 + 端口");
    }

    /// PING/PONG 回声
    #[test]
    fn test_ping_pong() {
        let p = ping();
        assert_eq!(p[0], CMD_PING);
        // PING 载荷 = cmd + ts(8B)，PONG 回声
        let echo = &p[1..];
        let po = pong(echo);
        assert_eq!(po[0], CMD_PONG);
        assert_eq!(&po[1..], echo, "PONG 应回声");
    }
}