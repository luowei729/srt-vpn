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

// ============================================================================
// 数据面载荷加密（2026-08-20 性能优化：SHA256 密钥流 -> AES-128-CTR）
//
// 改造原因（吞吐优化核心）：旧 SHA256 密钥流 XOR 单核仅 ~76MB/s（每 1316B 包
// 要做 42 次 SHA256 派生），双端收发各过一层 -> 回环吞吐 11MB/s 且 CPU 打满
// 116%（CPU bound 实锤）。AES-128-CTR 有 AES-NI 硬件加速，实测 ~2.4GB/s
// （32 倍提升），且 libsrt HaiCrypt 本就是 AES-128--**特征上更贴近真 SRT**。
//
// 语义变化：
// - 加密对象：一个完整数据壳包的 inner 载荷（STREAM/PING/PONG/RST 帧字节）
// - nonce（16B，CTR 需要 128bit 初始计数器）= [8B 连接随机前缀 | 8B 包号 BE]
//   * 包号全连接唯一（所有数据壳包共享 next_pkt_num 序列）-> 密钥流永不重复
//     （流密码安全核心），等价于旧"每包随机 nonce"且省掉 rand 系统调用
//   * nonce 与密文一起传输（[nonce || ciphertext]），接收方拿包号即可重建
// - 长度不变（CTR 无填充），保持包长分布与真 SRT 一致（伪装约束）
// ============================================================================


/// 连接级加密上下文（持有 AES 密钥 + 连接随机 nonce 前缀）
///
/// 每连接一个（密钥来自 passphrase 派生，前缀连接建立时随机生成）。
/// 加密函数按包号推导完整 nonce，无内部可变状态--天然线程安全。
pub struct PacketCipher {
    /// AES-128 密钥（16B）
    key: [u8; 16],
    /// nonce 前 8 字节（连接级随机；后 8 字节 = 包号，每包不同）
    nonce_prefix: [u8; 8],
}

impl PacketCipher {
    /// 创建连接加密上下文（密钥 + 随机 nonce 前缀）
    pub fn new(key: [u8; 16]) -> Self {
        use rand::RngCore;
        let mut nonce_prefix = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce_prefix);
        Self { key, nonce_prefix }
    }

    /// 加密一个数据壳包载荷
    ///
    /// 返回 `[nonce(16B) || ciphertext]`（与旧 encrypt_block 布局一致，
    /// 前端接收逻辑不变）。CTR 是流密码对称运算，解密同函数。
    pub fn encrypt_packet(&self, pkt_num: u64, plaintext: &[u8]) -> Vec<u8> {
        use aes::cipher::{KeyIvInit, StreamCipher};
        type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

        // nonce = 前缀(8B) || 包号(8B BE)：包号唯一保证密钥流不重复
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.nonce_prefix);
        nonce[8..].copy_from_slice(&pkt_num.to_be_bytes());

        let mut out = Vec::with_capacity(16 + plaintext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plaintext);
        // 就地加密 out 的密文区（避免再分配一次）
        let mut cipher = Aes128Ctr::new(&self.key.into(), (&nonce).into());
        cipher.apply_keystream(&mut out[16..]);
        out
    }

    /// 解密一个数据壳包载荷（输入 = [nonce(16B) || ciphertext]）
    pub fn decrypt_packet(&self, data: &[u8]) -> Option<Vec<u8>> {
        use aes::cipher::{KeyIvInit, StreamCipher};
        type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

        if data.len() < 16 {
            return None; // 连 nonce 都放不下，非法包
        }
        let (nonce, ct) = data.split_at(16);
        let nonce: [u8; 16] = nonce.try_into().ok()?;
        let mut plain = ct.to_vec();
        let mut cipher = Aes128Ctr::new(&self.key.into(), (&nonce).into());
        cipher.apply_keystream(&mut plain);
        Some(plain)
    }
}

/// 用密钥流 XOR 加密一块数据（流式，长度不变）
///（已被 PacketCipher 取代，2026-08-20 性能优化删除；
///  保留说明：旧实现见 git 历史 commit daa2674 之前版本）
#[cfg(test)]
mod tests {
    use super::*;

    /// AES-CTR 加解密往返
    #[test]
    fn test_encrypt_roundtrip() {
        let key: [u8; 16] = derive_key(b"passphrase", &[0u8; 16], KEY_LEN_128)
            .try_into()
            .unwrap();
        let cipher = PacketCipher::new(key);
        let plain = b"hello srt vpn 2026";
        let ct = cipher.encrypt_packet(42, plain);
        assert_ne!(&ct[16..], &plain[..], "密文不应等于明文");
        let pt = cipher.decrypt_packet(&ct).expect("解密失败");
        assert_eq!(pt, plain, "加解密往返应一致");
    }

    /// 相同明文不同包号产生不同密文（nonce 含包号，密钥流不重复）
    #[test]
    fn test_different_pkt_num() {
        let key: [u8; 16] = derive_key(b"p", &[1u8; 16], KEY_LEN_128)
            .try_into()
            .unwrap();
        let cipher = PacketCipher::new(key);
        let plain = b"aaaaaaaa";
        let c1 = cipher.encrypt_packet(0, plain);
        let c2 = cipher.encrypt_packet(1, plain);
        assert_ne!(c1, c2, "包号不同密文应不同");
        // 同包号重发密文一致（确定性，重传场景幂等）
        let c3 = cipher.encrypt_packet(0, plain);
        assert_eq!(c1, c3, "同包号应产生相同密文");
    }

    /// 长数据（跨多个 AES 块）往返一致
    #[test]
    fn test_long_roundtrip() {
        let key: [u8; 16] = derive_key(b"long-pass", &[9u8; 16], KEY_LEN_128)
            .try_into()
            .unwrap();
        let cipher = PacketCipher::new(key);
        let plain = vec![0x41; 2000]; // 2000B 跨多个 16B AES 块
        let ct = cipher.encrypt_packet(7, &plain);
        let pt = cipher.decrypt_packet(&ct).unwrap();
        assert_eq!(pt, plain, "长数据往返一致");
    }

    /// 不同连接（不同 nonce 前缀）相同包号密文不同
    #[test]
    fn test_different_connection() {
        let key: [u8; 16] = derive_key(b"conn-key", &[2u8; 16], KEY_LEN_128)
            .try_into()
            .unwrap();
        let c1 = PacketCipher::new(key);
        let c2 = PacketCipher::new(key);
        let plain = b"same data";
        // 极小概率前缀相同（2^-64），忽略
        let e1 = c1.encrypt_packet(5, plain);
        let e2 = c2.encrypt_packet(5, plain);
        assert_ne!(e1, e2, "不同连接前缀应产生不同密文");
    }

    /// 非法输入（< nonce 长度）返回 None
    #[test]
    fn test_invalid_input() {
        let key: [u8; 16] = [1u8; 16];
        let cipher = PacketCipher::new(key);
        assert!(cipher.decrypt_packet(&[0u8; 15]).is_none(), "短于 nonce 应拒绝");
        assert!(cipher.decrypt_packet(&[0u8; 16]).is_some(), "恰好 nonce 长度（空载荷）合法");
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