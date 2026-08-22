//! SRT 0x80 外壳编解码模块
//!
//! 设计原因：DPI 通过 UDP 包首字节识别协议类型。标准 QUIC 首包首字节 0xC0
//! （Long Header + TLS ClientHello 明文），一眼就被识别不是 SRT。
//! 解决方案：在每个 UDP 包前加 16 字节 SRT 外壳头，使 DPI 认为是 SRT 流量。
//!
//! SRT 外壳格式（参照 libsrt 1.5.6 srtcore/packet.h）：
//! ```
//! ┌──────────────────────────────────────────────────────────────┐
//! │ 0-3   SEQNO:   bit31=0 数据 / =1 控制；bit30..16=消息类型；   │
//! │                bit15..0=扩展                                    │
//! │ 4-7   MSGNO:   bit31-30 边界；bit29 顺序；bit28-27 key 标志；  │
//! │                bit26 重传；bit25-0 消息序号                    │
//! │ 8-11  TIMESTAMP: 32 位微秒时间戳                               │
//! │ 12-15 ID:       目标 socket ID                                 │
//! ├── 内层：AES-128-CTR 密文（加密后的 QUIC 包）──────────────────┤
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! 控制包类型（bit31=1）：
//! - HANDSHAKE(0)：首包握手，首 4B = 0x80 00 00 00
//! - KEEPALIVE(1)：保活
//! - ACK(2)：确认，首 4B = 0x80 02 00 00
//! - NAK(3)：否定确认
//! - SHUTDOWN(5)：关闭
//!
//! 数据包（bit31=0）：首字节 0x00-0x7f

use std::time::Instant;

/// SRT 外壳固定头长度（16 字节）
pub const SRT_HEADER_LEN: usize = 16;

/// 仿真目标：DPI 将流量识别为 RTP/SRT 而非“未知 UDP”
/// - 真 SRT live 模式固定包长 1328 字节（1312 载荷 + 16 头，188*7 MPEG-TS）
/// - 我们固定 wire 长度到 SRT_WIRE_SIZE，QUIC 包先加 2 字节长度前缀再 pad，解密时按长度截取
pub const SRT_WIRE_SIZE: usize = 1328;
/// 单个 SRT 数据包的载荷容量（wire 长度减头）
pub const SRT_DATA_PAYLOAD_SIZE: usize = SRT_WIRE_SIZE - SRT_HEADER_LEN; // 1312
/// 长度前缀字节数（密文前 2 字节 BE 长度）
pub const SRT_LEN_PREFIX: usize = 2;

/// 将密文打包为固定长度载荷：[2B 长度 BE][密文][pad 0 到 1312]
/// 原因：真 SRT live 固定 1328 字节，防火墙按包长识别 RTP/SRT；加密后载荷随机无需 TS 同步字节
pub fn pack_fixed_payload(ciphertext: &[u8]) -> Vec<u8> {
    debug_assert!(ciphertext.len() + SRT_LEN_PREFIX <= SRT_DATA_PAYLOAD_SIZE);
    let mut out = Vec::with_capacity(SRT_DATA_PAYLOAD_SIZE);
    out.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out.resize(SRT_DATA_PAYLOAD_SIZE, 0);
    out
}

/// 从固定长度载荷还原密文：按前 2 字节长度截取；若长度非法或非固定包则原样返回（兼容旧版不定长包）
pub fn unpack_fixed_payload(payload: &[u8]) -> Vec<u8> {
    if payload.len() == SRT_DATA_PAYLOAD_SIZE && payload.len() >= SRT_LEN_PREFIX {
        let len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if len <= SRT_DATA_PAYLOAD_SIZE - SRT_LEN_PREFIX && len > 0 {
            // 额外校验：pad 区域应全 0（避免误判旧版随机载荷首 2 字节恰好小值）
            // 旧版载荷加密后随机，pad 区非全 0 的概率极高；全 0 则认为是固定包
            let pad_is_zero = payload[SRT_LEN_PREFIX + len..].iter().all(|&b| b == 0);
            if pad_is_zero || len + SRT_LEN_PREFIX + 16 <= payload.len() {
                // 放宽：只要长度合理就按固定包处理（兼容 pad 非全 0 的边界）
                return payload[SRT_LEN_PREFIX..SRT_LEN_PREFIX + len].to_vec();
            }
        }
        // 长度非法或 pad 非 0：回退为兼容模式（可能是旧版不定长包恰好 1312）
        // 尝试按长度截取，失败则原样
        if len <= payload.len() - SRT_LEN_PREFIX {
            return payload[SRT_LEN_PREFIX..SRT_LEN_PREFIX + len].to_vec();
        }
    }
    // 非固定包或控制包：原样返回
    payload.to_vec()
}

/// SRT 控制包标志位（SEQNO 字段的 bit31）
const SRT_CTRL_FLAG: u32 = 0x80000000;

/// SRT 控制包类型掩码（SEQNO 字段的 bit30..16）
const SRT_CTRL_TYPE_MASK: u32 = 0x7FFF0000;

/// SRT 控制包类型右移位数
const SRT_CTRL_TYPE_SHIFT: u32 = 16;

/// SRT 控制包类型枚举
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrlType {
    /// 握手（首包，0x80 00 00 00）
    Handshake = 0,
    /// 保活
    Keepalive = 1,
    /// 确认
    Ack = 2,
    /// 否定确认（丢包通知）
    Nak = 3,
    /// 关闭连接
    Shutdown = 5,
}

impl CtrlType {
    /// 从 u16 转换为 CtrlType
    fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Handshake),
            1 => Some(Self::Keepalive),
            2 => Some(Self::Ack),
            3 => Some(Self::Nak),
            5 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

/// SRT 外壳包类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrtPacket {
    /// 控制包（握手/ACK/NAK/保活/关闭）
    Control {
        /// 控制包类型
        ctrl_type: CtrlType,
        /// 扩展字段（SEQNO 的 bit15..0）
        ext: u16,
        /// 消息序号
        msg_no: u32,
        /// 微秒时间戳
        timestamp: u32,
        /// 目标 socket ID
        socket_id: u32,
        /// 负载数据（控制包的附加信息）
        payload: Vec<u8>,
    },
    /// 数据包
    Data {
        /// 序列号（SEQNO 字段，bit31=0）
        seq: u32,
        /// 消息号
        msg_no: u32,
        /// 微秒时间戳
        timestamp: u32,
        /// 目标 socket ID
        socket_id: u32,
        /// 负载数据（加密后的 QUIC 数据包）
        payload: Vec<u8>,
    },
}

impl SrtPacket {
    /// 获取负载数据
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Control { payload, .. } => payload,
            Self::Data { payload, .. } => payload,
        }
    }

    /// 是否为控制包
    pub fn is_control(&self) -> bool {
        matches!(self, Self::Control { .. })
    }

    /// 创建握手控制包
    ///
    /// 首 4 字节为 0x80 00 00 00（SRT 握手包特征）
    pub fn handshake(ext: u16, msg_no: u32, socket_id: u32, payload: Vec<u8>) -> Self {
        Self::Control {
            ctrl_type: CtrlType::Handshake,
            ext,
            msg_no,
            timestamp: 0, // 握手首包时间戳为 0
            socket_id,
            payload,
        }
    }

    /// 创建数据包
    pub fn data(seq: u32, msg_no: u32, timestamp: u32, socket_id: u32, payload: Vec<u8>) -> Self {
        Self::Data {
            seq,
            msg_no,
            timestamp,
            socket_id,
            payload,
        }
    }

    /// 创建 ACK 控制包
    pub fn ack(seq: u32, msg_no: u32, socket_id: u32) -> Self {
        Self::Control {
            ctrl_type: CtrlType::Ack,
            ext: 0,
            msg_no,
            timestamp: Self::now_timestamp(),
            socket_id,
            payload: seq.to_be_bytes().to_vec(), // ACK 序号放在负载里
        }
    }

    /// 获取当前微秒时间戳（相对于程序启动）
    ///
    /// SRT 时间戳是 32 位微秒，会回绕。用相对时间即可。
    pub fn now_timestamp() -> u32 {
        use std::sync::OnceLock;
        static START: OnceLock<Instant> = OnceLock::new();
        let start = START.get_or_init(Instant::now);
        (start.elapsed().as_micros() as u32)
    }

    /// 编码为字节缓冲区
    ///
    /// 在 QUIC 包前面加 16 字节 SRT 头，使 DPI 认为是 SRT 流量。
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SRT_HEADER_LEN + self.payload().len());
        self.encode_into(&mut buf);
        buf
    }

    /// 编码到已有的 BufMut（避免额外分配）
    fn encode_into<B: bytes::BufMut>(&self, buf: &mut B) {
        match self {
            Self::Control {
                ctrl_type,
                ext,
                msg_no,
                timestamp,
                socket_id,
                payload,
            } => {
                // SEQNO: bit31=1(控制) + bit30..16=类型 + bit15..0=ext
                let seqno = SRT_CTRL_FLAG
                    | ((*ctrl_type as u32) << SRT_CTRL_TYPE_SHIFT)
                    | (*ext as u32);
                buf.put_u32(seqno);
                buf.put_u32(*msg_no); // MSGNO
                buf.put_u32(*timestamp); // TIMESTAMP
                buf.put_u32(*socket_id); // ID
                buf.put_slice(payload);
            }
            Self::Data {
                seq,
                msg_no,
                timestamp,
                socket_id,
                payload,
            } => {
                // SEQNO: bit31=0(数据)，seq 为数据包序号
                // 注意：seq 的 bit31 必须为 0，确保是数据包
                let seqno = seq & 0x7FFFFFFF; // 清除 bit31
                buf.put_u32(seqno);
                buf.put_u32(*msg_no);
                buf.put_u32(*timestamp);
                buf.put_u32(*socket_id);
                buf.put_slice(payload);
            }
        }
    }

    /// 从字节切片解码 SRT 包
    ///
    /// 去掉 16 字节 SRT 头，返回包类型和负载（加密的 QUIC 包）。
    pub fn decode(data: &[u8]) -> Result<Self, SrtError> {
        if data.len() < SRT_HEADER_LEN {
            return Err(SrtError::TooShort);
        }

        let seqno = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let msg_no = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let timestamp = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let socket_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        let payload = data[SRT_HEADER_LEN..].to_vec();

        if seqno & SRT_CTRL_FLAG != 0 {
            // 控制包：bit31=1
            let ctrl_type_u16 = ((seqno & SRT_CTRL_TYPE_MASK) >> SRT_CTRL_TYPE_SHIFT) as u16;
            let ext = (seqno & 0xFFFF) as u16;
            let ctrl_type = CtrlType::from_u16(ctrl_type_u16)
                .ok_or(SrtError::InvalidCtrlType(ctrl_type_u16))?;

            Ok(Self::Control {
                ctrl_type,
                ext,
                msg_no,
                timestamp,
                socket_id,
                payload,
            })
        } else {
            // 数据包：bit31=0
            Ok(Self::Data {
                seq: seqno,
                msg_no,
                timestamp,
                socket_id,
                payload,
            })
        }
    }
}

/// SRT 外壳解码错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrtError {
    /// 数据太短（不足 16 字节头）
    TooShort,
    /// 无效的控制包类型
    InvalidCtrlType(u16),
    /// 不是合法 RTP 包（V != 2，用于驱动区分 RTP 外壳与旧 SRT 外壳）
    InvalidRtpVersion,
}

impl std::fmt::Display for SrtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SrtError::TooShort => write!(f, "SRT 包数据太短（不足 16 字节头）"),
            SrtError::InvalidCtrlType(t) => write!(f, "无效 SRT 控制包类型: {}", t),
            SrtError::InvalidRtpVersion => write!(f, "非 RTP 包（V != 2）"),
        }
    }
}

impl std::error::Error for SrtError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_encode_decode() {
        let pkt = SrtPacket::handshake(0, 0, 0x12345678, vec![1, 2, 3]);
        let encoded = pkt.encode();
        assert_eq!(encoded.len(), SRT_HEADER_LEN + 3);

        // 首 4 字节应为 0x80 00 00 00（SRT 握手特征）
        assert_eq!(&encoded[0..4], &[0x80, 0x00, 0x00, 0x00]);

        let decoded = SrtPacket::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn test_data_encode_decode() {
        let pkt = SrtPacket::data(0x1234, 1, 999, 0xABCDEF01, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let encoded = pkt.encode();

        // 首 4 字节 bit31=0（数据包）
        assert_eq!(encoded[0] & 0x80, 0x00);

        let decoded = SrtPacket::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn test_ack_encode_decode() {
        let pkt = SrtPacket::ack(42, 1, 0x12345678);
        let encoded = pkt.encode();

        // 首 4 字节应为 0x80 02 00 00（ACK 控制包）
        assert_eq!(&encoded[0..4], &[0x80, 0x02, 0x00, 0x00]);

        let decoded = SrtPacket::decode(&encoded).unwrap();
        match decoded {
            SrtPacket::Control { ctrl_type, .. } => {
                assert_eq!(ctrl_type, CtrlType::Ack);
            }
            _ => panic!("应为控制包"),
        }
    }

    #[test]
    fn test_decode_too_short() {
        let data = [0u8; 15]; // 不足 16 字节
        assert!(matches!(SrtPacket::decode(&data), Err(SrtError::TooShort)));
    }

    #[test]
    fn test_control_packet_first_byte() {
        // 所有控制包首字节最高位必须为 1（0x80）
        let handshake = SrtPacket::handshake(0, 0, 0, vec![]).encode();
        let ack = SrtPacket::ack(0, 0, 0).encode();
        assert_eq!(handshake[0] & 0x80, 0x80);
        assert_eq!(ack[0] & 0x80, 0x80);
    }

    #[test]
    fn test_data_packet_first_byte() {
        // 数据包首字节最高位必须为 0
        let data_pkt = SrtPacket::data(0x7FFFFFFF, 0, 0, 0, vec![]).encode();
        assert_eq!(data_pkt[0] & 0x80, 0x00);
    }
}
