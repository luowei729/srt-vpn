//! quic/crypto.rs — 载荷加密（自研，SRT 特征密钥派生）
//!
//! 设计（重构共识决策 E：认证学 SRT 特征，防主动探测）：
//! - 继承 libsrt 的 passphrase 加密模型：用户 passphrase → 密钥派生（标准 KDF）
//! - 载荷加密：**密钥流 XOR**（仿 SRT/HaiCrypt 的流式加密语义）：密钥流由
//!   SHA256(passphrase派生密钥 || nonce || 计数器) 生成，与明文 XOR。
//!   - 无数据包边界填充，长度与明文一致（保持包长分布与真 SRT 一致）
//!   - 语义等价"流式加密"，特征与 libsrt 的 kmreq 对齐
//! - 密钥派生：仿 libsrt pbkdf（passphrase + salt + 重复迭代），SRT 特征
//!
//! 无 C 依赖（只 sha2，纯 Rust）——符合重构共识"彻底废弃 libsrt/C 依赖"。
//!
//! ⚠️ 安全说明：此模块是 VPN 隧道加密，密钥来自 passphrase（用户配置强密码）。
//! 目标是与 libsrt 行为对齐（若 DPI 只抓包无法解密），重点在流量特征与性能。

use sha2::{Digest, Sha256};

/// 密钥派生盐长度
/// P1.5 接入数据面加解密时启用
#[allow(dead_code)]
pub const SALT_LEN: usize = 16;
/// 派生密钥长度（与 libsrt 的 AES-128 对齐：16B）
pub const KEY_LEN_128: usize = 16;
/// PBKDF 迭代次数（仿 libsrt 风格，防离线暴力）
const PBKDF_ITERATIONS: u32 = 10_000;
/// 密钥流生成块的字节数（SHA256 输出 32B 一块）
/// P1.5 接入数据面加解密时启用
#[allow(dead_code)]
const KEYSTREAM_BLOCK: usize = 32;

/// 派生内容加密密钥（passphrase + salt -> 密钥，PBKDF2 风格简化）
///
/// 仿 libsrt 的 pbkdf 行为（passphrase + salt 迭代 SHA256），对齐密钥派生特征。
pub fn derive_key(passphrase: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    let mut base = {
        let mut h = Sha256::new();
        h.update(passphrase);
        h.update(salt);
        h.finalize().to_vec()
    };
    let mut filled = 0usize;
    while filled < key_len {
        // 迭代压缩：对 base 迭代 SHA256
        for _ in 0..PBKDF_ITERATIONS {
            let mut hh = Sha256::new();
            hh.update(base.as_slice());
            base = hh.finalize().to_vec();
        }
        let n = (key_len - filled).min(base.len());
        key[filled..filled + n].copy_from_slice(&base[..n]);
        filled += n;
        // 继续扩展下一块
        let mut h3 = Sha256::new();
        h3.update(base.as_slice());
        base = h3.finalize().to_vec();
    }
    key
}

/// 生成随机盐
/// P1.5 接入数据面加解密时启用
#[allow(dead_code)]
pub fn random_salt() -> [u8; SALT_LEN] {
    use rand::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// 用密钥流 XOR 加密一块数据（流式，长度不变）
///（P1.5 接入数据面加解密时启用）
///
/// - key: derive_key 产出的密钥
/// - nonce: 12B 随机 nonce（SRT 加密的密钥派生语义，每块不同 => 密钥流不同）
/// - plaintext: 明文
///
/// 返回 [nonce || ciphertext]（nonce 前置，接收方无需额外协商）
#[allow(dead_code)]
pub fn encrypt_block(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nonce.len() + plaintext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&xor_keystream(key, nonce, plaintext));
    out
}

/// 解密（encrypt_block 的对称操作——流加密对称，密钥流 XOR 回可得明文）
///（P1.5 接入数据面加解密时启用）
#[allow(dead_code)]
pub fn decrypt_block(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let (nonce, ct) = data.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    Some(xor_keystream(key, &nonce, ct))
}

/// 生成密钥流并 XOR 到数据（每 KEYSTREAM_BLOCK 字节派生一次密钥流块）
///
/// 密钥流 = SHA256(key || nonce || 块索引)，伪随机伸展，与明文 XOR。
///（P1.5 接入数据面加解密时启用）
#[allow(dead_code)]
fn xor_keystream(key: &[u8], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    // 逐块处理（每 KEYSTREAM_BLOCK 字节一块，密钥流块不同）
    let mut chunk_start = 0usize;
    while chunk_start < data.len() {
        let chunk_end = (chunk_start + KEYSTREAM_BLOCK).min(data.len());
        let ks = keystream(chunk_start / KEYSTREAM_BLOCK, key, nonce);
        for i in chunk_start..chunk_end {
            out[i] = data[i] ^ ks[i - chunk_start];
        }
        chunk_start += KEYSTREAM_BLOCK;
    }
    out
}

/// 生成一个密钥流块（SHA256 抽象 XOR 流，每块派生一次）
///（P1.5 接入数据面加解密时启用）
#[allow(dead_code)]
fn keystream(block: usize, key: &[u8], nonce: &[u8; 12]) -> [u8; KEYSTREAM_BLOCK] {
    let mut h = Sha256::new();
    h.update(key);
    h.update(nonce.as_slice());
    // 块索引加入派生（每个块密钥流不同）
    let block_bytes = (block as u64).to_be_bytes();
    h.update(block_bytes.as_slice());
    let digest = h.finalize().to_vec();
    let mut out = [0u8; KEYSTREAM_BLOCK];
    // SHA256 输出 32B 正好一块
    out[..digest.len().min(KEYSTREAM_BLOCK)].copy_from_slice(&digest[..digest.len().min(KEYSTREAM_BLOCK)]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 加解密往返
    #[test]
    fn test_encrypt_roundtrip() {
        let key = derive_key(b"passphrase", &[0u8; 16], KEY_LEN_128);
        let nonce = [7u8; 12];
        let plain = b"hello srt vpn 2026";
        let ct = encrypt_block(&key, &nonce, plain);
        assert_ne!(ct[12..], plain[..], "密文不应等于明文");
        let pt = decrypt_block(&key, &ct).expect("解密失败");
        assert_eq!(pt, plain, "加解密往返应一致");
    }

    /// 相同明文不同 nonce 产生不同密文
    #[test]
    fn test_different_nonce() {
        let key = derive_key(b"p", &[1u8; 16], KEY_LEN_128);
        let plain = b"aaaaaaaa";
        let c1 = encrypt_block(&key, &[0u8; 12], plain);
        let c2 = encrypt_block(&key, &[1u8; 12], plain);
        assert_ne!(c1, c2, "nonce 不同密文应不同");
    }

    /// 长数据（跨多个密钥流块）往返一致
    #[test]
    fn test_long_roundtrip() {
        let key = derive_key(b"long-pass", &[9u8; 16], KEY_LEN_128);
        let nonce = [3u8; 12];
        let plain = vec![0x41; 200]; // 200B 跨 7 个 32B 块
        let ct = encrypt_block(&key, &nonce, &plain);
        let pt = decrypt_block(&key, &ct).unwrap();
        assert_eq!(pt, plain, "长数据往返一致");
    }

    /// 密钥派生确定性 + 长度
    #[test]
    fn test_derive_deterministic() {
        let k1 = derive_key(b"secret", b"salt1234567890", KEY_LEN_128);
        let k2 = derive_key(b"secret", b"salt1234567890", KEY_LEN_128);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), KEY_LEN_128);
    }
}