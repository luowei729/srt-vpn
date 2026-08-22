//! RTP 外壳编解码模块（RFC3550 §5.1，2026-08-22 新增）
//!
//! 设计原因：DPI 对 UDP 首字节识别协议类型。标准 QUIC 首包 0xC0、SRT 数据包
//! bit31=0（首字节 0x00-0x7F）都被判"未知 UDP"。真实 RTP 视频流首字节固定
//! 0x80（V=2），被防火墙识别为媒体流。本项目把 SRT 外壳升级为 RTP 外壳，
//! 使 DPI 将隧道流量识别为"RTP 视频流"而非未知 UDP。
//!
//! RTP 固定头（RFC3550，12 字节）：
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|X|  CC   |M|     PT      |       sequence number         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           timestamp                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           synchronization source (SSRC) identifier            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! 拟真参数（对照真 RTP H264 抓包）：
//! - V=2, P=0, X=0, CC=0 → 首字节固定 0x80
//! - PT=96（动态视频 H264 常用值）
//! - SEQ：16bit 每包 +1（连续，回绕）
//! - TS：90000Hz 采样时钟，每 2 包一帧（30fps → 帧间 TS 增 3000）
//! - M：奇数包=1（帧尾），偶数包=0（帧首）→ 拟真低码率视频每帧 2 包
//! - SSRC：连接级固定随机值（RTP 会话内不变）
//!
//! 载荷格式：[8B 包号 BE][AES-128-CTR 密文(QUIC 包)]
//! - 包号用于构造 AES nonce（[8B 连接前缀][8B 包号]，见 crypto.rs），
//!   与现有 SRT 模式加密完全复用，保证 nonce 唯一且两端可恢复。
//! - 密文随机，nDPI 等主流 DPI 判 RTP 只看头不校验负载内容。

/// RTP 固定头长度（12 字节）
pub const RTP_HEADER_LEN: usize = 12;

/// 动态视频载荷类型（H264 常用值 96）
pub const RTP_PT_VIDEO: u8 = 96;

/// 采样时钟频率（视频标准 90000Hz）
pub const RTP_CLOCK_RATE: u32 = 90000;

/// 每帧 TS 增量（30fps → 90000/30 = 3000）
pub const RTP_TS_PER_FRAME: u32 = 3000;

/// 包号前缀长度（载荷前 8B 存加密包号）
pub const RTP_PKTNUM_LEN: usize = 8;

/// RTCP Sender Report 包长（RFC3550 §6.4.1，无 report block 的最小 SR = 28B）
pub const RTCP_SR_LEN: usize = 28;

/// RTCP Sender Report (SR) 载荷类型（PT=200，nDPI is_valid_rtcp 192-213 有效）
pub const RTCP_PT_SR: u8 = 200;

/// 构造 RTCP Sender Report 包（28B，无 report block）
///
/// 设计原因：真实 RTP 视频会话标配 RTCP SR 控制通道（周期上报发送统计），
/// 部分简化 DPI（如爱快/OpenWrt 面板）要求 RTP+RTCP 成对才识别为视频流。
/// 周期注入一个合法 SR 包能显著提升这类 DPI 的识别率。
///
/// 字段（RFC3550 §6.4.1）：
/// - byte0: V=2(10) P=0 RC=0 → 0x80
/// - byte1: PT=200 (SR)
/// - byte2-3: length = (28/4)-1 = 6（word 计数 - 1）
/// - byte4-7: sender SSRC（与 RTP 流同 SSRC，保持一致）
/// - byte8-15: NTP 时间戳（64bit，秒+分数）
/// - byte16-19: RTP 时间戳（与最近发送的 RTP TS 对齐）
/// - byte20-23: 发送方累计包数
/// - byte24-27: 发送方累计字节数
pub fn build_rtcp_sr(ssrc: u32, rtp_timestamp: u32, packet_count: u32, octet_count: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RTCP_SR_LEN);
    buf.push(0x80); // V=2, P=0, RC=0
    buf.push(RTCP_PT_SR); // PT=200
    buf.extend_from_slice(&6u16.to_be_bytes()); // length
    buf.extend_from_slice(&ssrc.to_be_bytes());
    // NTP 时间戳（简化：用固定高秒 + 递增低分）
    buf.extend_from_slice(&0x12345678u32.to_be_bytes());
    buf.extend_from_slice(&0x9abcdef0u32.to_be_bytes());
    buf.extend_from_slice(&rtp_timestamp.to_be_bytes());
    buf.extend_from_slice(&packet_count.to_be_bytes());
    buf.extend_from_slice(&octet_count.to_be_bytes());
    buf
}

/// 判断一段 UDP 载荷是否为合法 RTCP SR 包（供驱动接收端识别控制包）
pub fn is_rtcp_sr(data: &[u8]) -> bool {
    data.len() >= RTCP_SR_LEN
        && (data[0] >> 6) & 0x3 == 2
        && data[1] == RTCP_PT_SR
        && u16::from_be_bytes([data[2], data[3]]) == 6
}

/// RTP 外壳包
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    /// 标记位（帧尾 = 1，帧首 = 0）
    pub marker: bool,
    /// 载荷类型（PT）
    pub pt: u8,
    /// 序号（16bit，每包 +1）
    pub seq: u16,
    /// 时间戳（32bit，90000Hz 采样时钟）
    pub timestamp: u32,
    /// 同步源标识（连接级固定）
    pub ssrc: u32,
    /// 负载：[8B 包号 BE][AES 密文]
    pub payload: Vec<u8>,
}

impl RtpPacket {
    /// 创建数据包
    ///
    /// # 参数
    /// - `seq`: RTP 序号（驱动维护的 16bit 计数器）
    /// - `ssrc`: 同步源 ID（每连接随机固定）
    /// - `payload`: [8B 包号 BE][AES 密文]
    pub fn data(seq: u16, ssrc: u32, payload: Vec<u8>) -> Self {
        // TS = (seq>>1)*3000：每 2 包一帧，30fps 视频节奏
        // M = seq&1：奇数包帧尾置 1
        let timestamp = ((seq as u32) >> 1) * RTP_TS_PER_FRAME;
        let marker = seq & 1 == 1;
        Self {
            marker,
            pt: RTP_PT_VIDEO,
            seq,
            timestamp,
            ssrc,
            payload,
        }
    }

    /// 获取负载中的包号（前 8B BE）
    ///
    /// 用于构造 AES nonce 解密（与 crypto.rs decrypt_with_nonce 一致）。
    pub fn packet_num(&self) -> Option<u64> {
        if self.payload.len() < RTP_PKTNUM_LEN {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.payload[..RTP_PKTNUM_LEN]);
        Some(u64::from_be_bytes(buf))
    }

    /// 获取去掉包号前缀后的密文
    pub fn ciphertext(&self) -> &[u8] {
        if self.payload.len() < RTP_PKTNUM_LEN {
            return &[];
        }
        &self.payload[RTP_PKTNUM_LEN..]
    }

    /// 编码为字节缓冲区（12B RTP 头 + 负载）
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RTP_HEADER_LEN + self.payload.len());
        // 字节0：V=2(10) | P=0 | X=0 | CC=0 → 0x80
        buf.push(0x80);
        // 字节1：M | PT
        buf.push((if self.marker { 0x80 } else { 0 }) | (self.pt & 0x7F));
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// 从字节切片解码 RTP 包
    ///
    /// 校验：长度 ≥ 12、V=2（首字节 0x80-0xBF）、PT 0-127、负载含包号前缀。
    /// 失败返回 SrtError（与 srt_shell 共用错误类型便于驱动分支处理）。
    pub fn decode(data: &[u8]) -> Result<Self, crate::transport::srt_shell::SrtError> {
        if data.len() < RTP_HEADER_LEN {
            return Err(crate::transport::srt_shell::SrtError::TooShort);
        }
        let b0 = data[0];
        let b1 = data[1];
        // V 必须 = 2（b0 高 2 位 = 10b → 0x80-0xBF）
        if (b0 >> 6) & 0x3 != 2 {
            return Err(crate::transport::srt_shell::SrtError::InvalidRtpVersion);
        }
        let marker = b1 & 0x80 != 0;
        let pt = b1 & 0x7F;
        let seq = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let payload = data[RTP_HEADER_LEN..].to_vec();
        // 负载至少要有 8B 包号前缀
        if payload.len() < RTP_PKTNUM_LEN {
            return Err(crate::transport::srt_shell::SrtError::TooShort);
        }
        Ok(Self {
            marker,
            pt,
            seq,
            timestamp,
            ssrc,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_header_fields() {
        // 构造 4 个连续包，验证 RTP 头字段符合视频流拟真节奏
        let mut pkts = Vec::new();
        for seq in 0..4u16 {
            let pkt = RtpPacket::data(seq, 0x12345678, vec![0; RTP_PKTNUM_LEN + 8]);
            let enc = pkt.encode();
            assert_eq!(enc.len(), RTP_HEADER_LEN + RTP_PKTNUM_LEN + 8);
            // 首字节必须 0x80（V=2）
            assert_eq!(enc[0], 0x80);
            // PT=96
            assert_eq!(enc[1] & 0x7F, RTP_PT_VIDEO);
            pkts.push(pkt);
        }
        // SEQ 连续 +1
        for i in 0..3 {
            assert_eq!(pkts[i + 1].seq, pkts[i].seq.wrapping_add(1));
        }
        // TS：每 2 包增 3000
        assert_eq!(pkts[0].timestamp, 0);
        assert_eq!(pkts[1].timestamp, 0);
        assert_eq!(pkts[2].timestamp, RTP_TS_PER_FRAME);
        // M：奇数包帧尾
        assert!(!pkts[0].marker);
        assert!(pkts[1].marker);
        assert!(!pkts[2].marker);
        assert!(pkts[3].marker);
        // SSRC 固定
        assert_eq!(pkts[0].ssrc, 0x12345678);
        assert_eq!(pkts[3].ssrc, 0x12345678);
    }

    #[test]
    fn test_rtp_encode_decode_roundtrip() {
        // 包号前缀 + 密文 roundtrip
        let payload = {
            let mut p = Vec::new();
            p.extend_from_slice(&42u64.to_be_bytes());
            p.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
            p
        };
        let pkt = RtpPacket::data(101, 0xDEADBEEF, payload); // 奇数 seq → 帧尾 marker=1
        let enc = pkt.encode();
        let dec = RtpPacket::decode(&enc).unwrap();
        assert_eq!(dec.seq, 101);
        assert_eq!(dec.ssrc, 0xDEADBEEF);
        assert_eq!(dec.marker, true);
        assert_eq!(dec.packet_num(), Some(42));
        assert_eq!(dec.ciphertext(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_rtcp_sr_build_and_detect() {
        // 构造 RTCP SR，验证字段合法且能被 is_rtcp_sr 识别
        let sr = build_rtcp_sr(0xcfeb9550, 3000, 100, 120000);
        assert_eq!(sr.len(), RTCP_SR_LEN);
        assert_eq!(sr[0], 0x80); // V=2
        assert_eq!(sr[1], RTCP_PT_SR); // PT=200
        assert_eq!(u16::from_be_bytes([sr[2], sr[3]]), 6); // length
        assert!(is_rtcp_sr(&sr));
        // 非 RTCP 包应识别失败
        assert!(!is_rtcp_sr(&[0x80, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!is_rtcp_sr(&[0x80, 200, 0, 6, 0])); // 太短
    }

    #[test]
    fn test_rtp_decode_rejects_non_rtp() {
        // 首字节不是 V=2（如 SRT 数据包 0x00 开头）应拒绝
        let bad = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(RtpPacket::decode(&bad).is_err());
        // 太短
        assert!(RtpPacket::decode(&[0x80, 0x60, 0x00, 0x01]).is_err());
    }
}
