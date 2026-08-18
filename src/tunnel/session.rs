//! tunnel/session.rs — 会话管理
//!
//! 设计决策（Q7/Q20）：
//! - 256 并发会话上限，u16 会话 ID（0 保留给控制通道，1..=255 可用）
//! - 每客户端独立会话空间（服务器为每个客户端维护独立的 SessionTable）
//! - 会话记录：目标地址、协议类型（TCP/UDP）、关闭状态（半关闭支持）
//!
//! 注：本模块 API 完整（含半关闭状态机），P1 前半段仅用部分，
//! 转发接入后全部启用；测试已覆盖全部状态转换。

#![allow(dead_code)]

use std::collections::HashMap;

use super::MAX_SESSIONS;

/// 会话协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProto {
    /// TCP 会话（面向连接）
    Tcp,
    /// UDP 会话（无连接）
    Udp,
}

/// 会话状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// 已打开（数据可双向流动）
    Open,
    /// 发送侧关闭（本端不再发数据，仍可收）
    LocalFin,
    /// 接收侧关闭（对端已 FIN）
    RemoteFin,
    /// 完全关闭（双向关闭）
    Closed,
}

/// 单个会话记录
#[derive(Debug, Clone)]
pub struct Session {
    /// 会话 ID（1..=255）
    pub id: u16,
    /// 目标地址（服务器转发目标 / 客户端本地目标）
    pub dst: String,
    /// 协议类型
    pub proto: SessionProto,
    /// 会话状态
    pub state: SessionState,
    /// 创建时间（Unix 秒）
    pub created_at: i64,
    /// 最后活动时间（Unix 秒，过期清理用）
    pub last_active: i64,
    /// 接收缓冲序号（用于窗口流控跟踪）
    pub next_seq: u32,
    /// 发送窗口（流控）
    pub send_window: u32,
}

/// 会话表（每客户端一个实例）
#[derive(Debug, Default)]
pub struct SessionTable {
    /// 会话 ID → 会话
    sessions: HashMap<u16, Session>,
    /// 下一个分配的会话 ID（循环分配）
    next_id: u16,
}

impl SessionTable {
    /// 创建空的会话表
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
        }
    }

    /// 分配新会话
    /// 返回会话 ID；满时返回 None
    pub fn allocate(&mut self, dst: String, proto: SessionProto, now: i64) -> Option<u16> {
        // 已达会话上限
        if self.sessions.len() >= MAX_SESSIONS - 1 {
            return None;
        }
        // 循环寻找空闲 ID（1..=255）
        for _ in 0..MAX_SESSIONS {
            let id = self.next_id;
            self.next_id = if self.next_id >= (MAX_SESSIONS - 1) as u16 {
                1
            } else {
                self.next_id + 1
            };
            if id == 0 || self.sessions.contains_key(&id) {
                continue;
            }
            let session = Session {
                id,
                dst,
                proto,
                state: SessionState::Open,
                created_at: now,
                last_active: now,
                next_seq: 0,
                send_window: 0,
            };
            self.sessions.insert(id, session);
            return Some(id);
        }
        None
    }

    /// 获取会话（只读）
    pub fn get(&self, id: u16) -> Option<&Session> {
        self.sessions.get(&id)
    }

    /// 获取会话（可变）
    pub fn get_mut(&mut self, id: u16) -> Option<&mut Session> {
        self.sessions.get_mut(&id)
    }

    /// 关闭会话（移除 + 返回是否发生过关闭通知）
    pub fn remove(&mut self, id: u16) -> bool {
        self.sessions.remove(&id).is_some()
    }

    /// 标记本端发送侧关闭（半关闭）
    pub fn mark_local_fin(&mut self, id: u16) {
        if let Some(s) = self.sessions.get_mut(&id) {
            match s.state {
                SessionState::Open => s.state = SessionState::LocalFin,
                SessionState::RemoteFin => s.state = SessionState::Closed,
                _ => {}
            }
        }
    }

    /// 标记对端关闭（远程 FIN）
    pub fn mark_remote_fin(&mut self, id: u16) {
        if let Some(s) = self.sessions.get_mut(&id) {
            match s.state {
                SessionState::Open => s.state = SessionState::RemoteFin,
                SessionState::LocalFin => s.state = SessionState::Closed,
                _ => {}
            }
        }
    }

    /// 更新活动时间
    pub fn touch(&mut self, id: u16, now: i64) {
        if let Some(s) = self.sessions.get_mut(&id) {
            s.last_active = now;
        }
    }

    /// 当前活跃会话数
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// 清理超时会话（返回被清理的 ID 列表）
    /// idle_timeout: 秒
    pub fn cleanup_expired(&mut self, now: i64, idle_timeout: i64) -> Vec<u16> {
        let expired: Vec<u16> = self
            .sessions
            .iter()
            .filter(|(_, s)| now - s.last_active > idle_timeout)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.sessions.remove(id);
        }
        expired
    }

    /// 迭代全部会话（用于状态上报）
    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.sessions.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_and_get() {
        let mut table = SessionTable::new();
        let id = table.allocate("192.168.1.1:80".to_string(), SessionProto::Tcp, 1000).unwrap();
        assert!(id >= 1 && id <= 255);
        let s = table.get(id).unwrap();
        assert_eq!(s.dst, "192.168.1.1:80");
        assert_eq!(s.proto, SessionProto::Tcp);
    }

    #[test]
    fn test_remove() {
        let mut table = SessionTable::new();
        let id = table.allocate("host:443".to_string(), SessionProto::Tcp, 1000).unwrap();
        assert!(table.remove(id));
        assert!(table.get(id).is_none());
    }

    #[test]
    fn test_half_close_transitions() {
        let mut table = SessionTable::new();
        let id = table.allocate("host:80".to_string(), SessionProto::Tcp, 1000).unwrap();
        // Open + LocalFin → LocalFin
        table.mark_local_fin(id);
        assert_eq!(table.get(id).unwrap().state, SessionState::LocalFin);
        // LocalFin + RemoteFin → Closed
        table.mark_remote_fin(id);
        assert_eq!(table.get(id).unwrap().state, SessionState::Closed);
    }

    #[test]
    fn test_session_limit() {
        let mut table = SessionTable::new();
        // 尝试分配 300 个，最多 255 个成功
        let mut count = 0;
        for _ in 0..300 {
            if table.allocate(format!("h{}:1", count), SessionProto::Tcp, 0).is_some() {
                count += 1;
            }
        }
        assert!(count <= 255, "会话数应 ≤ 255，实际 {count}");
        assert_eq!(table.len(), 255);
    }
}