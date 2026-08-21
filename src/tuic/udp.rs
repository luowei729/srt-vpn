//! TUIC UDP 分片重组模块
//!
//! 设计原因：TUIC 协议支持将大 UDP 数据包分片为多个 Packet 命令发送。
//! 每片携带 assoc_id + pkt_id + frag_total + frag_id，
//! 首片携带完整地址，非首片地址为 None。
//! 接收端按 (assoc_id, pkt_id) 聚合分片，收到全部分片后重组完整数据包。
//!
//! 分片重组需要处理：
//! - 乱序到达（不同分片可能乱序）
//! - 重复分片（重传导致的重复）
//! - 过期清理（未完成的分片组超时清理，防内存泄漏）

use crate::tuic::addr::Address;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 单个分片信息（重组缓冲区中暂存）
#[derive(Debug, Clone)]
struct Fragment {
    /// 分片序号
    frag_id: u8,
    /// 分片数据
    data: Vec<u8>,
    /// 到达时间（用于过期清理）
    arrived_at: Instant,
}

/// 分片组（同一 pkt_id 的所有分片集合）
#[derive(Debug)]
struct FragmentGroup {
    /// 分片总数（从首片获取）
    frag_total: Option<u8>,
    /// 首片的地址（从首片获取，非首片无地址）
    addr: Option<Address>,
    /// 已收到的分片列表
    fragments: Vec<Fragment>,
}

impl FragmentGroup {
    fn new() -> Self {
        Self {
            frag_total: None,
            addr: None,
            fragments: Vec::new(),
        }
    }

    /// 添加分片，返回是否已收齐全部分片
    fn add_fragment(&mut self, frag: Fragment, frag_total: u8, addr: &Address) -> bool {
        // 首片（frag_id=0 且 addr != None）携带 frag_total 和 addr
        if frag.frag_id == 0 && !matches!(addr, Address::None) {
            self.frag_total = Some(frag_total);
            self.addr = Some(addr.clone());
        }

        // 跳过重复分片（相同 frag_id 已存在则跳过）
        if self.fragments.iter().any(|f| f.frag_id == frag.frag_id) {
            return false;
        }

        self.fragments.push(frag);

        // 检查是否已收齐全部分片
        if let Some(total) = self.frag_total {
            return self.fragments.len() == total as usize;
        }
        false
    }

    /// 重组完整数据包（分片按 frag_id 排序后拼接）
    ///
    /// 返回 (地址, 完整 payload)
    fn reassemble(&self) -> Option<(Address, Vec<u8>)> {
        let addr = self.addr.clone()?;
        let total = self.frag_total?;

        if self.fragments.len() != total as usize {
            return None;
        }

        // 按 frag_id 排序后拼接
        let mut frags = self.fragments.clone();
        frags.sort_by_key(|f| f.frag_id);

        let mut payload = Vec::new();
        for frag in frags {
            payload.extend_from_slice(&frag.data);
        }

        Some((addr, payload))
    }
}

/// UDP 分片重组器
///
/// 按 (assoc_id, pkt_id) 聚合分片，收齐后返回完整数据包。
/// 支持过期清理防止内存泄漏。
#[derive(Debug)]
pub struct FragmentReassemblyBuffer {
    /// 分片组表：key = (assoc_id, pkt_id)
    groups: HashMap<(u16, u16), FragmentGroup>,
    /// 过期超时时间（默认 30 秒）
    timeout: Duration,
}

impl FragmentReassemblyBuffer {
    /// 创建新的重组器
    ///
    /// # 参数
    /// - `timeout`: 分片组过期超时（未完成的分片组超时后清理）
    pub fn new(timeout: Duration) -> Self {
        Self {
            groups: HashMap::new(),
            timeout,
        }
    }

    /// 添加一个分片
    ///
    /// 返回 Some((addr, payload)) 表示已收齐并重组成功，
    /// 返回 None 表示还在等待更多分片。
    pub fn add_fragment(
        &mut self,
        assoc_id: u16,
        pkt_id: u16,
        frag_id: u8,
        frag_total: u8,
        addr: &Address,
        payload: Vec<u8>,
        now: Instant,
    ) -> Option<(Address, Vec<u8>)> {
        let key = (assoc_id, pkt_id);
        let group = self.groups.entry(key).or_insert_with(FragmentGroup::new);

        let fragment = Fragment {
            frag_id,
            data: payload,
            arrived_at: now,
        };

        // 添加分片，检查是否收齐
        if group.add_fragment(fragment, frag_total, addr) {
            // 收齐，重组并移除分组
            let result = group.reassemble();
            self.groups.remove(&key);
            return result;
        }

        None
    }

    /// 清理过期分片组
    ///
    /// 应定期调用（如每 GC 间隔），防止未完成分片组堆积泄漏内存。
    pub fn cleanup_expired(&mut self, now: Instant) {
        let timeout = self.timeout;
        self.groups.retain(|_, group| {
            // 检查组内最早到达的分片是否已超时
            let oldest = group.fragments.iter().map(|f| f.arrived_at).min();
            match oldest {
                Some(t) => now.duration_since(t) < timeout,
                None => true, // 无分片的组保留（理论上不会出现）
            }
        });
    }

    /// 清除指定关联的所有分片（关联断开时调用）
    pub fn remove_assoc(&mut self, assoc_id: u16) {
        self.groups.retain(|(aid, _), _| *aid != assoc_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_single_fragment() {
        // 无分片（frag_total=1）应立即重组
        let mut reassembler = FragmentReassemblyBuffer::new(Duration::from_secs(30));
        let addr = Address::ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let now = Instant::now();

        let result = reassembler.add_fragment(1, 0, 0, 1, &addr, vec![1, 2, 3], now);
        assert!(result.is_some());
        let (decoded_addr, payload) = result.unwrap();
        assert_eq!(decoded_addr, addr);
        assert_eq!(payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_multiple_fragments_ordered() {
        // 有序到达的多分片
        let mut reassembler = FragmentReassemblyBuffer::new(Duration::from_secs(30));
        let addr = Address::ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let now = Instant::now();

        // 分片 0（首片，带地址）
        let r1 = reassembler.add_fragment(1, 0, 0, 3, &addr, vec![1, 2], now);
        assert!(r1.is_none());

        // 分片 1
        let r2 = reassembler.add_fragment(1, 0, 1, 3, &Address::None, vec![3, 4], now);
        assert!(r2.is_none());

        // 分片 2（最后一片，应触发重组）
        let r3 = reassembler.add_fragment(1, 0, 2, 3, &Address::None, vec![5, 6], now);
        assert!(r3.is_some());

        let (decoded_addr, payload) = r3.unwrap();
        assert_eq!(decoded_addr, addr);
        assert_eq!(payload, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_multiple_fragments_unordered() {
        // 乱序到达的多分片
        let mut reassembler = FragmentReassemblyBuffer::new(Duration::from_secs(30));
        let addr = Address::ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let now = Instant::now();

        // 分片 2 先到
        reassembler.add_fragment(1, 0, 2, 3, &Address::None, vec![5, 6], now);
        // 分片 0（首片）
        reassembler.add_fragment(1, 0, 0, 3, &addr, vec![1, 2], now);
        // 分片 1 最后到（触发重组）
        let result = reassembler.add_fragment(1, 0, 1, 3, &Address::None, vec![3, 4], now);
        assert!(result.is_some());

        let (_, payload) = result.unwrap();
        assert_eq!(payload, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_duplicate_fragments() {
        // 重复分片应被跳过，不破坏重组
        let mut reassembler = FragmentReassemblyBuffer::new(Duration::from_secs(30));
        let addr = Address::ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let now = Instant::now();

        // 分片 0
        reassembler.add_fragment(1, 0, 0, 2, &addr, vec![1, 2], now);
        // 分片 0 重复（应跳过）
        reassembler.add_fragment(1, 0, 0, 2, &addr, vec![1, 2], now);
        // 分片 1（触发重组）
        let result = reassembler.add_fragment(1, 0, 1, 2, &Address::None, vec![3, 4], now);
        assert!(result.is_some());

        let (_, payload) = result.unwrap();
        assert_eq!(payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut reassembler = FragmentReassemblyBuffer::new(Duration::from_millis(100));
        let addr = Address::ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let now = Instant::now();

        // 添加一个未完成的分片组
        reassembler.add_fragment(1, 0, 0, 2, &addr, vec![1, 2], now);

        // 等待超时后清理
        let later = now + Duration::from_millis(200);
        reassembler.cleanup_expired(later);

        // 分片组应被清理
        assert!(reassembler.groups.is_empty());
    }

    #[test]
    fn test_remove_assoc() {
        let mut reassembler = FragmentReassemblyBuffer::new(Duration::from_secs(30));
        let addr = Address::ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let now = Instant::now();

        // 两个不同关联的分片组
        reassembler.add_fragment(1, 0, 0, 2, &addr, vec![1], now);
        reassembler.add_fragment(2, 0, 0, 2, &addr, vec![2], now);

        // 清除关联 1
        reassembler.remove_assoc(1);

        // 关联 2 应保留
        assert_eq!(reassembler.groups.len(), 1);
        assert!(reassembler.groups.contains_key(&(2, 0)));
    }
}
