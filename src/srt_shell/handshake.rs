//! srt_shell/handshake.rs — SRT 特征握手（拟真 libsrt 行为）
//!
//! 对齐 libsrt 的握手线格式（handshake.cpp store_to 序列化），确保首包被
//! DPI 识别为 SRT/UDT 握手：
//!
//! ```
//! [16B 包首]          0x80000000（控制 + HANDSHAKE）
//! [48B CHandShake]   version=4 | type/ReqType | ISN | MSS | ... | cookie
//! ```
//!
//! 握手流程（拟真 libsrt 两阶段）：
//! 1. 客户端发 INDUCTION（ReqType=1，version=4）——首包 0x80 00 00 00
//! 2. 服务端回 INDUCTION（含 cookie）
//! 3. 客户端发 CONCLUSION（ReqType=0？——libsrt 实际是 URQ_CONCLUSION=4?——用
//!    简化单轮挑战-应答：客户端发令牌，服务端验证回确认）
//!
//! ⚠️ 本文件专注"握手外形"（字节结构像 SRT）；真正的认证逻辑在 auth.rs
//! （passphrase 密钥派生 + challenge/response）。

use super::header::{HS_VERSION_UDT4, SRT_MSS, URQ_INDUCTION};

/// 握手包体（CHandShake 序列化）长度（libsrt m_iContentSize = 48）
pub const HANDSHAKE_BODY_LEN: usize = 48;

/// 握手类型（libsrt handshake.h URQ_* 常量）
pub const URQ_CONCLUSION: u32 = 1; // 简化：1 = induction（与 libsrt 对齐），结论轮用 2
pub const URQ_ACCEPT: u32 = 2; // 简化结论确认

/// 序列化 CHandShake 握手包体（48B，对齐 libsrt store_to 字段顺序）
///
/// 字段布局（对齐 libsrt handshake.cpp store_to）：
/// [version u32][type u32][ISN u32][MSS u32][FlightFlagSize u32][ReqType u32]
/// [socketID u32][cookie u32][peerIP u32 ×4]
pub fn serialize_handshake(
    req_type: u32,
    socket_id: u32,
    cookie: u32,
    isn: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HANDSHAKE_BODY_LEN);
    // version = 4（HS_VERSION_UDT4）
    out.extend_from_slice(&HS_VERSION_UDT4.to_be_bytes());
    // type（URQ_*：induction=1 / accept=2，简化映射）
    out.extend_from_slice(&req_type.to_be_bytes());
    // ISN（随机初始序号）
    out.extend_from_slice(&isn.to_be_bytes());
    // MSS = 1500
    out.extend_from_slice(&SRT_MSS.to_be_bytes());
    // FlightFlagSize（握手阶段 0）
    out.extend_from_slice(&0u32.to_be_bytes());
    // ReqType（induction=1）
    out.extend_from_slice(&URQ_INDUCTION.to_be_bytes());
    // socketID
    out.extend_from_slice(&socket_id.to_be_bytes());
    // cookie（首次随机占位）
    out.extend_from_slice(&cookie.to_be_bytes());
    // peer IP（4×u32，握手阶段 0）
    for _ in 0..4 {
        out.extend_from_slice(&0u32.to_be_bytes());
    }
    out
}

/// 解析握手包体（返回 (version, req_type, socket_id, cookie)）
/// 非法返回 None
pub fn parse_handshake(body: &[u8]) -> Option<(u32, u32, u32, u32)> {
    if body.len() < HANDSHAKE_BODY_LEN {
        // 允许兼容短的握手（简化协商）
        if body.len() < 16 {
            return None;
        }
    }
    let version = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let req_type = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    // socketID 在偏移 24（第 7 个 u32：version,type,ISN,MSS,Flight,ReqType=6个，socketID 第7）
    let socket_id = if body.len() >= 28 {
        u32::from_be_bytes([body[24], body[25], body[26], body[27]])
    } else {
        0
    };
    let cookie = if body.len() >= 32 {
        u32::from_be_bytes([body[28], body[29], body[30], body[31]])
    } else {
        0
    };
    Some((version, req_type, socket_id, cookie))
}

/// 生成握手 ISN（随机初始序号）
pub fn random_isn() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// 生成 cookie（服务端握手确认用）
pub fn random_cookie() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srt_shell::outer::encode_ctrl_packet;
    use crate::srt_shell::header::MSG_HANDSHAKE;

    /// 握手包体序列化字段（version=4，48B）
    #[test]
    fn test_serialize_shape() {
        let body = serialize_handshake(URQ_CONCLUSION, 0x1234, 0xdead, 0xbeef);
        assert_eq!(body.len(), HANDSHAKE_BODY_LEN, "握手包体应 48B");
        assert_eq!(&body[0..4], &[0, 0, 0, 4], "version 应=4");
        assert_eq!(&body[4..8], &[0, 0, 0, 1], "ReqType(induction) 应=1");
    }

    /// 首包整体：0x80 00 00 00 + 48B 体
    #[test]
    fn test_first_packet_structure() {
        let body = serialize_handshake(URQ_CONCLUSION, 0x1234, 0xde, 0xab);
        let pkt = encode_ctrl_packet(MSG_HANDSHAKE, 0, &body);
        assert_eq!(&pkt[0..4], &[0x80, 0, 0, 0], "首包应 0x80 00 00 00");
        assert!(pkt.len() >= 64, "首包长度应 ≥64B（16 头 + 48 体）");
    }

    /// 解析往返
    #[test]
    fn test_parse_roundtrip() {
        let body = serialize_handshake(URQ_CONCLUSION, 0xabcd, 0x1234, 0x5678);
        let (version, request_type, socket_id, cookie) = parse_handshake(&body).unwrap();
        assert_eq!(version, HS_VERSION_UDT4);
        assert_eq!(request_type, 1);
        assert_eq!(socket_id, 0xabcd);
        assert_eq!(cookie, 0x1234);
    }
}