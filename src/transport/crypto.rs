//! 双阶段 AES-128-CTR 包级加密模块
//!
//! 设计原因：quinn-proto 生成的 QUIC 包（含 TLS ClientHello 明文）如果不加密，
//! DPI 跳过 SRT 头后仍能识别 QUIC 长头格式。所以必须对 QUIC 包整体加密。
//!
//! 双阶段密钥派生：
//! 1. **阶段 1（TLS 握手前）**：用 passphrase 经 PBKDF2 派生临时 AES-128 密钥，
//!    加密 quinn-proto 生成的 Initial 包（含 ClientHello）。
//! 2. **阶段 2（TLS 握手完成后）**：调用 `conn.crypto_session().export_keying_material()`
//!    派生 32B 会话密钥材料，取前 16B 作为 AES-128-CTR 密钥替换临时密钥。
//!
//! 加密方式：AES-128-CTR（AES-NI 硬件加速，性能开销几乎为零）
//! Nonce 设计：[8B 连接前缀 + 8B 包号 BE]，包号唯一保证密钥流不重复。

use aes::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;

/// AES-128-CTR 加密器/解密器（对称，同一实例可加可解）
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// AES-128 密钥长度（16 字节）
pub const KEY_LEN: usize = 16;

/// Nonce 长度（16 字节 = 8B 连接前缀 + 8B 包号）
pub const NONCE_LEN: usize = 16;

/// 包级加密器
///
/// 负责对 quinn-proto 输出的 QUIC 包进行 AES-128-CTR 加密/解密。
/// 加密后的包套 SRT 外壳发送。
pub struct PacketCipher {
    /// AES-128 密钥（16 字节）
    key: [u8; KEY_LEN],
    /// 连接前缀（8 字节，每个连接唯一，用于 nonce 多样化）
    conn_prefix: [u8; 8],
    /// 当前包号（递增，用于 nonce）
    packet_num: u64,
}

impl PacketCipher {
    /// 创建新的加密器
    ///
    /// # 参数
    /// - `key`: AES-128 密钥（16 字节）
    /// - `conn_prefix`: 连接前缀（8 字节，每连接唯一）
    pub fn new(key: [u8; KEY_LEN], conn_prefix: [u8; 8]) -> Self {
        Self {
            key,
            conn_prefix,
            packet_num: 0,
        }
    }

    /// 从 passphrase 派生临时密钥（阶段 1：TLS 握手前用）
    ///
    /// 使用 PBKDF2-HMAC-SHA256 从 passphrase 派生 16 字节密钥。
    /// 客户端和服务端用相同 passphrase + 固定盐 → 相同密钥。
    pub fn derive_temp_key(passphrase: &str) -> [u8; KEY_LEN] {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;

        // 固定盐（客户端和服务端必须一致，用项目标识做盐确保唯一性）
        const SALT: &[u8] = b"srt-vpn-v0.4-temp-key-salt";
        const ITERATIONS: u32 = 10000; // PBKDF2 迭代次数

        let mut key = [0u8; KEY_LEN];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), SALT, ITERATIONS, &mut key);
        key
    }

    /// 从 TLS exporter 派生会话密钥（阶段 2：TLS 握手后用）
    ///
    /// 调用 `conn.crypto_session().export_keying_material()` 派生 32 字节，
    /// 取前 16 字节作为 AES-128 密钥。
    ///
    /// # 参数
    /// - `exporter_fn`: TLS exporter 回调（label=UUID, context=password → 32B）
    ///   客户端和服务端用相同 UUID+password → 相同 exporter 输出
    pub fn derive_session_key<F>(exporter_fn: F) -> Result<[u8; KEY_LEN], CryptoError>
    where
        F: FnOnce(&mut [u8], &[u8], &[u8]) -> Result<(), ExportKeyError>,
    {
        let mut material = [0u8; 32];
        // label 和 context 由调用方传入（TUIC 认证用 UUID 做 label，password 做 context）
        // 这里只调用 exporter_fn 获取密钥材料
        exporter_fn(&mut material, b"", b"")
            .map_err(|_| CryptoError::ExportKeyFailed)?;

        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&material[..KEY_LEN]);
        Ok(key)
    }

    /// 从 passphrase 派生连接前缀（8 字节）
    ///
    /// 两端用相同 passphrase → 相同 conn_prefix → 相同 nonce 基础
    /// （阶段 1 临时密钥期间使用）
    pub fn derive_conn_prefix(passphrase: &str) -> [u8; 8] {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;

        const SALT: &[u8] = b"srt-vpn-v0.4-conn-prefix";
        let mut material = [0u8; 8];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), SALT, 10000, &mut material);
        material
    }

    /// 生成随机连接前缀（8 字节）
    ///
    /// 用于阶段 2（会话密钥），每连接唯一
    pub fn random_conn_prefix() -> [u8; 8] {
        let mut prefix = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut prefix);
        prefix
    }

    /// 更新会话密钥（阶段 2 切换时调用）
    ///
    /// TLS 握手完成后，用 exporter 派生的密钥替换临时密钥。
    pub fn update_key(&mut self, key: [u8; KEY_LEN]) {
        self.key = key;
        self.packet_num = 0; // 重置包号
    }

    /// 生成下一个 nonce
    ///
    /// Nonce = [8B 连接前缀][8B 包号 BE]
    /// 包号递增保证密钥流不重复。
    fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.conn_prefix);
        nonce[8..].copy_from_slice(&self.packet_num.to_be_bytes());
        self.packet_num = self.packet_num.wrapping_add(1);
        nonce
    }

    /// 加密 QUIC 包
    ///
    /// 对 quinn-proto 输出的 QUIC 包字节做 AES-128-CTR 加密。
    /// 加密后套 SRT 外壳发送。返回 (加密后的数据, 本次使用的包号)。
    /// 包号需嵌入 SRT 头传输给接收方用于解密。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> (Vec<u8>, u64) {
        // 先保存当前 packet_num（next_nonce 会递增它）
        let packet_num = self.packet_num;
        let nonce = self.next_nonce();
        let mut cipher = Aes128Ctr::new(&self.key.into(), &nonce.into());
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);
        (ciphertext, packet_num)
    }

    /// 解密 QUIC 包
    ///
    /// 对 SRT 外壳剥离后的密文做 AES-128-CTR 解密。
    /// 解密后喂回 quinn-proto 处理。
    ///
    /// # 参数
    /// - `ciphertext`: 密文
    /// - `conn_prefix`: 发送方连接前缀（从 SRT 头或外部获取）
    /// - `packet_num`: 发送方包号（从 SRT 头或外部获取）
    pub fn decrypt_with_nonce(
        &self,
        ciphertext: &[u8],
        conn_prefix: &[u8; 8],
        packet_num: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(conn_prefix);
        nonce[8..].copy_from_slice(&packet_num.to_be_bytes());

        let mut cipher = Aes128Ctr::new(&self.key.into(), &nonce.into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);
        Ok(plaintext)
    }

    /// 获取当前密钥（用于调试）
    pub fn key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// 获取连接前缀
    pub fn conn_prefix(&self) -> &[u8; 8] {
        &self.conn_prefix
    }
}

/// TLS exporter 错误类型（透传 quinn-proto 的错误）
#[derive(Debug)]
pub struct ExportKeyError;

/// 加密错误
#[derive(Debug)]
pub enum CryptoError {
    /// TLS exporter 派生密钥失败
    ExportKeyFailed,
    /// 解密失败
    DecryptFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::ExportKeyFailed => write!(f, "TLS exporter 密钥派生失败"),
            CryptoError::DecryptFailed => write!(f, "解密失败"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // 测试加密解密往返
        let key = [0x42u8; KEY_LEN];
        let prefix = [0x01u8; 8];
        let mut cipher = PacketCipher::new(key, prefix);

        let plaintext = b"Hello, QUIC World! ClientHello goes here.";
        let (ciphertext, packet_num) = cipher.encrypt(plaintext);

        // 密文应与明文不同
        assert_ne!(&ciphertext[..], &plaintext[..]);

        // 解密应恢复原文（用相同 nonce）
        let decrypted = cipher
            .decrypt_with_nonce(&ciphertext, &prefix, packet_num)
            .unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_derive_temp_key_consistent() {
        // 相同 passphrase 应派生出相同密钥
        let key1 = PacketCipher::derive_temp_key("my-passphrase");
        let key2 = PacketCipher::derive_temp_key("my-passphrase");
        assert_eq!(key1, key2);

        // 不同 passphrase 应派生出不同密钥
        let key3 = PacketCipher::derive_temp_key("other-passphrase");
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_key_update() {
        let mut cipher = PacketCipher::new([0x01u8; 16], [0x02u8; 8]);
        let plaintext = b"test data";

        // 用旧密钥加密
        let (ciphertext1, pkt_num1) = cipher.encrypt(plaintext);

        // 更新密钥
        cipher.update_key([0x03u8; 16]);

        // 用新密钥加密（应得到不同密文）
        let (ciphertext2, _pkt_num2) = cipher.encrypt(plaintext);
        assert_ne!(ciphertext1, ciphertext2);

        // 验证旧密文用旧密钥+旧 packet_num 能解密
        let mut cipher_old = PacketCipher::new([0x01u8; 16], [0x02u8; 8]);
        // cipher_old 的 packet_num 从 0 开始，但 encrypt 后变为 1
        // 需要用 pkt_num1 解密
        let decrypted = cipher_old.decrypt_with_nonce(&ciphertext1, &[0x02u8; 8], pkt_num1).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_empty_data() {
        let mut cipher = PacketCipher::new([0u8; 16], [0u8; 8]);
        let (ciphertext, packet_num) = cipher.encrypt(b"");
        assert!(ciphertext.is_empty());

        let decrypted = cipher.decrypt_with_nonce(&ciphertext, &[0u8; 8], packet_num).unwrap();
        assert!(decrypted.is_empty());
    }
}
