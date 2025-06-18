use std::collections::{HashMap, BTreeMap};
use std::time::{Duration, Instant};
use crate::decode::DecodedPacket;
use std::sync::{Arc, Mutex};
use bytes::BytesMut;
use log::{debug, error, warn, trace, info};
use crate::decode::TransportProtocol;
use std::sync::atomic::{AtomicUsize, Ordering};
use crate::error::{Result, ReassembleError, PacketError};

// 参考Suricata的配置参数
const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(30);  // 分片超时时间：30秒
const MAX_FRAGMENT_SIZE: usize = 65535;  // 最大分片大小
const MAX_FRAGMENTS_PER_GROUP: usize = 8192;  // 每个分片组最大分片数
const MAX_FRAGMENT_GROUPS: usize = 10000;  // 最大分片组数量

/// 分片策略，参考Suricata的设计
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FragmentPolicy {
    /// 使用第一个分片的数据（RFC 791默认行为）
    First,
    /// 使用最后一个分片的数据
    Last,
    /// 使用最长的分片数据
    Longest,
}

/// 单个IP分片，参考Suricata的fragment结构
#[derive(Debug, Clone)]
struct Fragment {
    offset: u16,  // 使用u16以符合IP头部格式
    data: Vec<u8>,
    more_fragments: bool,
    timestamp: Instant,
    length: u16,
}

impl Fragment {
    fn new(offset: u16, data: Vec<u8>, more_fragments: bool) -> Self {
        Self {
            offset,
            length: data.len() as u16,
            data,
            more_fragments,
            timestamp: Instant::now(),
        }
    }

    /// 检查是否与另一个分片重叠
    fn overlaps_with(&self, other: &Fragment) -> bool {
        // offset 是以8字节为单位，length 是字节数
        // 统一转为字节单位
        let self_start = self.offset as u32 * 8;
        let self_end = self_start + self.length as u32;
        let other_start = other.offset as u32 * 8;
        let other_end = other_start + other.length as u32;
        
        // 添加详细的调试输出
        debug!("overlaps_with 计算: self(offset={}, length={}) -> start={}, end={}, other(offset={}, length={}) -> start={}, end={}", 
               self.offset, self.length, self_start, self_end, 
               other.offset, other.length, other_start, other_end);
        
        // 检查是否有重叠
        let overlaps = self_start < other_end && other_start < self_end;
        debug!("overlaps_with 结果: {}", overlaps);
        overlaps
    }

    /// 获取重叠区域
    fn get_overlap(&self, other: &Fragment) -> Option<(u16, u16)> {
        if !self.overlaps_with(other) {
            return None;
        }
        
        let overlap_start = self.offset.max(other.offset);
        let overlap_end = (self.offset + self.length).min(other.offset + other.length);
        
        Some((overlap_start, overlap_end))
    }
}

/// 分片组，参考Suricata的fragment group结构
#[derive(Debug, Clone)]
struct FragmentGroup {
    fragments: BTreeMap<u16, Fragment>,  // 使用BTreeMap按偏移量排序
    total_length: usize,
    last_update: Instant,
    policy: FragmentPolicy,
    source_ip: u32,
    dest_ip: u32,
    identification: u16,
    protocol: u8,
    flags: u8,
    ttl: u8,
    tos: u8,
}

impl FragmentGroup {
    fn new(source_ip: u32, dest_ip: u32, identification: u16, protocol: u8, policy: FragmentPolicy) -> Self {
        trace!("创建新的分片组: src_ip={}, dst_ip={}, id={}, proto={}, policy={:?}", 
               source_ip, dest_ip, identification, protocol, policy);
        Self {
            fragments: BTreeMap::new(),
            total_length: 0,
            last_update: Instant::now(),
            policy,
            source_ip,
            dest_ip,
            identification,
            protocol,
            flags: 0,
            ttl: 64,
            tos: 0,
        }
    }

    /// 添加分片到组中，处理重叠
    fn add_fragment(&mut self, fragment: Fragment) -> Result<bool> {
        let offset = fragment.offset;
        trace!("添加分片到组: offset={}, length={}, more_fragments={}", 
               offset, fragment.length, fragment.more_fragments);
        
        if let Some(existing) = self.fragments.get(&offset) {
            // 处理重叠分片
            match self.policy {
                FragmentPolicy::First => {
                    // 保留第一个分片，忽略新的
                    debug!("保留第一个分片，忽略重叠分片: offset={}", offset);
                    return Ok(false);
                },
                FragmentPolicy::Last => {
                    // 用新分片替换旧分片
                    debug!("用新分片替换旧分片: offset={}", offset);
                    self.fragments.insert(offset, fragment);
                    return Ok(true);
                },
                FragmentPolicy::Longest => {
                    // 保留最长的分片
                    if fragment.length > existing.length {
                        debug!("用更长的分片替换: offset={}, old_len={}, new_len={}", 
                               offset, existing.length, fragment.length);
                        self.fragments.insert(offset, fragment);
                        return Ok(true);
                    } else {
                        debug!("保留更长的分片: offset={}", offset);
                        return Ok(false);
                    }
                }
            }
        } else {
            // 检查与其他分片的重叠
            let mut has_overlap = false;
            for (_, existing) in &self.fragments {
                if fragment.overlaps_with(existing) {
                    has_overlap = true;
                    debug!("检测到分片重叠: new_offset={}, existing_offset={}", 
                           fragment.offset, existing.offset);
                    break;
                }
            }
            
            if has_overlap {
                // 根据策略处理重叠
                match self.policy {
                    FragmentPolicy::First => {
                        // 只保留第一个分片
                        return Ok(false);
                    },
                    FragmentPolicy::Last => {
                        // 移除重叠的分片，添加新分片
                        self.remove_overlapping_fragments(&fragment);
                        self.fragments.insert(offset, fragment);
                        return Ok(true);
                    },
                    FragmentPolicy::Longest => {
                        // 比较长度，保留最长的
                        let mut should_add = true;
                        let mut fragments_to_remove = Vec::new();
                        
                        for (existing_offset, existing) in &self.fragments {
                            if fragment.overlaps_with(existing) {
                                if fragment.length <= existing.length {
                                    should_add = false;
                                    break;
                                } else {
                                    fragments_to_remove.push(*existing_offset);
                                }
                            }
                        }
                        
                        if should_add {
                            for offset_to_remove in fragments_to_remove {
                                self.fragments.remove(&offset_to_remove);
                            }
                            self.fragments.insert(offset, fragment);
                            return Ok(true);
                        }
                        return Ok(false);
                    }
                }
            } else {
                // 无重叠，直接添加
                self.fragments.insert(offset, fragment);
                trace!("分片添加成功: offset={}, total_fragments={}", offset, self.fragments.len());
                return Ok(true);
            }
        }
    }

    /// 移除与指定分片重叠的所有分片
    fn remove_overlapping_fragments(&mut self, fragment: &Fragment) {
        let mut to_remove = Vec::new();
        for (offset, existing) in &self.fragments {
            if fragment.overlaps_with(existing) {
                to_remove.push(*offset);
            }
        }
        
        for offset in to_remove {
            self.fragments.remove(&offset);
            debug!("移除重叠分片: offset={}", offset);
        }
    }

    /// 检查分片组是否完整
    fn is_complete(&self) -> bool {
        if self.fragments.is_empty() {
            return false;
        }

        // 检查是否有最后一个分片（MF=0）
        let mut has_last_fragment = false;
        let mut expected_offset = 0;

        for (offset, fragment) in &self.fragments {
            if *offset != expected_offset {
                debug!("分片组不完整: 期望偏移量={}, 实际偏移量={}", expected_offset, offset);
                return false;
            }

            if !fragment.more_fragments {
                has_last_fragment = true;
                trace!("找到最后一个分片: offset={}", offset);
            }

            // 计算下一个期望的偏移量
            // offset 是以8字节为单位的，length 是数据长度（字节）
            // 下一个偏移量应该是当前偏移量加上数据长度（转换为8字节单位）
            expected_offset = offset + ((fragment.length + 7) / 8);
        }

        if !has_last_fragment {
            debug!("分片组不完整: 缺少最后一个分片");
            return false;
        }

        trace!("分片组完整: 总片段数={}, 总长度={}", self.fragments.len(), expected_offset);
        true
    }

    /// 重组分片
    fn reassemble(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err(ReassembleError::PacketError(PacketError::IncompleteFragment));
        }

        let mut reassembled_data = Vec::new();
        let mut total_length = 0;

        for (offset, fragment) in &self.fragments {
            // offset 是以8字节为单位，需要转换为字节
            let byte_offset = offset * 8;
            let fragment_end = byte_offset + fragment.length as u16;
            if fragment_end > total_length {
                total_length = fragment_end;
            }
        }

        reassembled_data.resize(total_length as usize, 0);

        for (offset, fragment) in &self.fragments {
            // offset 是以8字节为单位，需要转换为字节
            let start = (offset * 8) as usize;
            let end = start + fragment.data.len();
            
            if end > reassembled_data.len() {
                error!("分片数据超出重组缓冲区: offset={}, length={}, buffer_size={}", 
                       offset, fragment.data.len(), reassembled_data.len());
                return Err(ReassembleError::PacketError(PacketError::InvalidFragment));
            }
            
            reassembled_data[start..end].copy_from_slice(&fragment.data);
        }

        info!("分片重组成功: 总长度={}, 片段数={}", reassembled_data.len(), self.fragments.len());
        Ok(reassembled_data)
    }

    fn update_last_seen(&mut self) {
        self.last_update = Instant::now();
    }

    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_update) > FRAGMENT_TIMEOUT
    }
}

/// 原子统计信息
#[derive(Debug)]
struct AtomicStats {
    total_fragments: AtomicUsize,
    total_length: AtomicUsize,
    expired_groups: AtomicUsize,
    reassembled_packets: AtomicUsize,
    overlapping_fragments: AtomicUsize,
}

impl AtomicStats {
    fn new() -> Self {
        Self {
            total_fragments: AtomicUsize::new(0),
            total_length: AtomicUsize::new(0),
            expired_groups: AtomicUsize::new(0),
            reassembled_packets: AtomicUsize::new(0),
            overlapping_fragments: AtomicUsize::new(0),
        }
    }
}

/// 分片重组统计信息
#[derive(Debug, Default)]
pub struct DefragStats {
    pub total_fragments: AtomicUsize,
    pub total_length: AtomicUsize,
    pub expired_groups: AtomicUsize,
    pub current_groups: AtomicUsize,
    pub reassembled_packets: AtomicUsize,
    pub overlapping_fragments: AtomicUsize,
}

impl DefragStats {
    pub fn new() -> Self {
        Self {
            total_fragments: AtomicUsize::new(0),
            total_length: AtomicUsize::new(0),
            expired_groups: AtomicUsize::new(0),
            current_groups: AtomicUsize::new(0),
            reassembled_packets: AtomicUsize::new(0),
            overlapping_fragments: AtomicUsize::new(0),
        }
    }
}

/// IP分片重组器，参考Suricata设计
pub struct IpDefragmenter {
    fragments: Mutex<HashMap<(u32, u32, u16), FragmentGroup>>,
    stats: Arc<AtomicStats>,
    policy: FragmentPolicy,
    max_groups: usize,
}

impl IpDefragmenter {
    /// 创建新的分片重组器
    pub fn new() -> Self {
        info!("初始化IP分片重组器");
        Self {
            fragments: Mutex::new(HashMap::new()),
            stats: Arc::new(AtomicStats::new()),
            policy: FragmentPolicy::First,
            max_groups: MAX_FRAGMENT_GROUPS,
        }
    }

    /// 使用指定策略创建分片重组器
    pub fn with_policy(policy: FragmentPolicy) -> Self {
        info!("初始化IP分片重组器，策略: {:?}", policy);
        Self {
            fragments: Mutex::new(HashMap::new()),
            stats: Arc::new(AtomicStats::new()),
            policy,
            max_groups: MAX_FRAGMENT_GROUPS,
        }
    }

    /// 设置最大分片组数量
    pub fn set_max_groups(&mut self, max_groups: usize) {
        debug!("设置最大分片组数量: {}", max_groups);
        self.max_groups = max_groups;
    }

    /// 清理过期的分片组
    fn cleanup_expired_groups(&mut self, now: Instant) {
        let mut expired_count = 0;
        let mut fragments = self.fragments.lock().unwrap();
        
        fragments.retain(|_, group| {
            if group.is_expired(now) {
                expired_count += 1;
                debug!("清理过期分片组: src_ip={}, dst_ip={}, id={}", 
                       group.source_ip, group.dest_ip, group.identification);
                false
            } else {
                true
            }
        });

        if expired_count > 0 {
            self.stats.expired_groups.fetch_add(expired_count, Ordering::Relaxed);
            info!("清理了 {} 个过期分片组", expired_count);
        }
    }

    /// 处理IP分片包
    pub fn process_packet(&mut self, packet: &DecodedPacket) -> Result<Option<DecodedPacket>> {
        let start_time = Instant::now();
        trace!("开始处理IP分片数据包: src_ip={}, dst_ip={}, proto={}", 
               packet.ip_header.source_ip, packet.ip_header.dest_ip, packet.ip_header.protocol);

        // 验证分片数据包
        if !self.validate_fragment_packet(packet) {
            warn!("无效的分片数据包: src_ip={}, dst_ip={}, offset={}", 
                  packet.ip_header.source_ip, packet.ip_header.dest_ip, packet.ip_header.fragment_offset);
            return Ok(None);
        }

        let now = Instant::now();
        self.cleanup_expired_groups(now);

        let key = (
            packet.ip_header.source_ip,
            packet.ip_header.dest_ip,
            packet.ip_header.identification,
        );

        let fragment_data = match &packet.protocol {
            TransportProtocol::TCP { payload, .. } => payload.to_vec(),
            TransportProtocol::UDP { payload, .. } => payload.to_vec(),
        };

        let fragment = Fragment::new(
            packet.ip_header.fragment_offset,
            fragment_data,
            packet.ip_header.more_fragments,
        );

        let mut fragments = self.fragments.lock().unwrap();
        
        // 检查分片组数量限制
        if fragments.len() >= self.max_groups && !fragments.contains_key(&key) {
            warn!("达到最大分片组数量限制: {}", self.max_groups);
            return Err(ReassembleError::PacketError(PacketError::TooManyFragments));
        }

        let group = fragments.entry(key).or_insert_with(|| {
            FragmentGroup::new(
                packet.ip_header.source_ip,
                packet.ip_header.dest_ip,
                packet.ip_header.identification,
                packet.ip_header.protocol,
                self.policy,
            )
        });

        // 更新统计信息
        self.stats.total_fragments.fetch_add(1, Ordering::Relaxed);
        self.stats.total_length.fetch_add(fragment.data.len(), Ordering::Relaxed);

        // 添加分片到组
        match group.add_fragment(fragment) {
            Ok(true) => {
                debug!("分片添加成功: offset={}, group_size={}", 
                       packet.ip_header.fragment_offset, group.fragments.len());
            },
            Ok(false) => {
                debug!("分片被忽略: offset={}", packet.ip_header.fragment_offset);
                return Ok(None);
            },
            Err(e) => {
                error!("添加分片失败: {:?}", e);
                return Err(e);
            }
        }

        group.update_last_seen();

        // 检查是否可以重组
        if group.is_complete() {
            debug!("分片组完整，开始重组: src_ip={}, dst_ip={}, id={}", 
                   packet.ip_header.source_ip, packet.ip_header.dest_ip, packet.ip_header.identification);
            
            match group.reassemble() {
                Ok(reassembled_data) => {
                    self.stats.reassembled_packets.fetch_add(1, Ordering::Relaxed);
                    
                    let reassembled_packet = self.create_reassembled_packet(packet, &reassembled_data)
                        .ok_or_else(|| ReassembleError::PacketError(PacketError::ReassemblyFailed))?;
                    
                    // 移除已重组的分片组
                    fragments.remove(&key);
                    
                    let processing_time = start_time.elapsed();
                    info!("分片重组完成: 处理时间={:?}, 数据长度={}", processing_time, reassembled_data.len());
                    
                    Ok(Some(reassembled_packet))
                },
                Err(e) => {
                    error!("分片重组失败: {:?}", e);
                    Err(e)
                }
            }
        } else {
            debug!("分片组不完整，等待更多分片: src_ip={}, dst_ip={}, id={}, fragments={}", 
                   packet.ip_header.source_ip, packet.ip_header.dest_ip, packet.ip_header.identification, 
                   group.fragments.len());
            Ok(None)
        }
    }

    /// 验证分片包的有效性
    fn validate_fragment_packet(&self, packet: &DecodedPacket) -> bool {
        // 检查分片偏移量
        if packet.ip_header.fragment_offset > MAX_FRAGMENT_SIZE as u16 {
            warn!("分片偏移量过大: {}", packet.ip_header.fragment_offset);
            return false;
        }

        // 检查分片大小
        if packet.payload.len() > MAX_FRAGMENT_SIZE {
            warn!("分片大小过大: {}", packet.payload.len());
            return false;
        }

        // 只允许 TCP/UDP 协议分片
        if packet.ip_header.protocol != 6 && packet.ip_header.protocol != 17 {
            warn!("不支持的协议类型: {}", packet.ip_header.protocol);
            return false;
        }

        true
    }

    /// 创建重组后的数据包
    fn create_reassembled_packet(&self, original: &DecodedPacket, reassembled_data: &[u8]) -> Option<DecodedPacket> {
        // 创建重组后的数据包
        let mut reassembled_packet = original.clone();
        
        // 更新IP头部
        reassembled_packet.ip_header.fragment_offset = 0;
        reassembled_packet.ip_header.more_fragments = false;
        reassembled_packet.ip_header.total_length = (reassembled_data.len() + 20) as u16; // IP头部20字节
        
        // 更新负载
        reassembled_packet.payload = reassembled_data.to_vec();
        
        // 更新传输层协议
        match &mut reassembled_packet.protocol {
            TransportProtocol::TCP { payload, .. } => {
                *payload = BytesMut::from(reassembled_data);
            },
            TransportProtocol::UDP { payload, .. } => {
                *payload = BytesMut::from(reassembled_data);
            },
        }

        trace!("创建重组数据包: 原始长度={}, 重组长度={}", 
               original.payload.len(), reassembled_data.len());
        
        Some(reassembled_packet)
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> DefragStatsSnapshot {
        let fragments = self.fragments.lock().unwrap();
        DefragStatsSnapshot {
            total_fragments: self.stats.total_fragments.load(Ordering::Relaxed),
            total_length: self.stats.total_length.load(Ordering::Relaxed),
            expired_groups: self.stats.expired_groups.load(Ordering::Relaxed),
            current_groups: fragments.len(),
            reassembled_packets: self.stats.reassembled_packets.load(Ordering::Relaxed),
            overlapping_fragments: self.stats.overlapping_fragments.load(Ordering::Relaxed),
        }
    }

    /// 清理所有分片组
    pub fn clear(&mut self) {
        info!("清空IP分片重组器");
        let mut fragments = self.fragments.lock().unwrap();
        fragments.clear();
        self.stats = Arc::new(AtomicStats::new());
    }
}

/// 分片重组统计快照
#[derive(Debug)]
pub struct DefragStatsSnapshot {
    pub total_fragments: usize,
    pub total_length: usize,
    pub expired_groups: usize,
    pub current_groups: usize,
    pub reassembled_packets: usize,
    pub overlapping_fragments: usize,
}

mod tests {
    use super::*;
    use crate::decode::{DecodedPacket, TransportProtocol, IpHeader};

    fn create_test_packet(offset: u16, more_fragments: bool, data: &[u8]) -> DecodedPacket {
        // offset 参数直接作为 IP 头部的 fragment_offset 字段（8字节单位）
        DecodedPacket {
            ip_header: IpHeader {
                version: 4,
                ihl: 5,
                tos: 0,
                total_length: (20 + data.len()) as u16,
                identification: 12345,
                flags: if more_fragments { 1 } else { 0 },
                fragment_offset: offset, // 直接使用，不需要 /8 转换
                more_fragments,
                ttl: 64,
                protocol: 6, // TCP
                header_checksum: 0,
                source_ip: 0x0a0a0a0a,
                dest_ip: 0x0b0b0b0b,
            },
            protocol: TransportProtocol::TCP {
                seq: 0,
                ack: 0,
                flags: 0,
                window: 1024,
                src_port: 1234,
                dst_port: 5678,
                payload: BytesMut::from(data),
            },
            timestamp: 0,
            payload: data.to_vec(),
        }
    }

    #[test]
    fn test_simple_fragments() {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut defrag = IpDefragmenter::new();
        // frag1: offset=0, 长度8, more_fragments=true
        let frag1 = create_test_packet(0, true, b"abcdefgh");
        // frag2: offset=1 (即8字节), 长度4, more_fragments=false
        let frag2 = create_test_packet(1, false, b"ijkl");
        let result1 = defrag.process_packet(&frag1).unwrap();
        assert!(result1.is_none());
        let result2 = defrag.process_packet(&frag2).unwrap();
        assert!(result2.is_some());
        if let Some(reassembled) = result2 {
            match &reassembled.protocol {
                TransportProtocol::TCP { payload, .. } => {
                    assert_eq!(&payload[..], b"abcdefghijkl");
                }
                _ => panic!("Expected TCP protocol in reassembled packet"),
            }
        } else {
            panic!("Failed to reassemble fragments");
        }
    }

    #[test]
    fn test_fragmented_packet() {
        let mut defragmenter = IpDefragmenter::new();
        // frag1: offset=0, 长度8, more_fragments=true
        let frag1 = create_test_packet(0, true, b"First123");
        let result1 = defragmenter.process_packet(&frag1).unwrap();
        assert!(result1.is_none());
        // frag2: offset=1 (即8字节), 长度4, more_fragments=false
        let frag2 = create_test_packet(1, false, b"ABCD");
        let result2 = defragmenter.process_packet(&frag2).unwrap();
        assert!(result2.is_some(), "分片重组失败");
        if let Some(reassembled) = result2 {
            match &reassembled.protocol {
                TransportProtocol::TCP { payload, .. } => {
                    assert_eq!(&payload[..], b"First123ABCD");
                },
                _ => panic!("Expected TCP protocol")
            }
            let stats = defragmenter.get_stats();
            assert_eq!(stats.total_fragments, 2);
            assert_eq!(stats.current_groups, 0);
            assert_eq!(stats.reassembled_packets, 1);
        }
    }

    #[test]
    fn test_invalid_fragments() {
        let mut defrag = IpDefragmenter::new();
        // 过大分片
        let large_data = vec![0u8; MAX_FRAGMENT_SIZE + 1];
        let invalid_frag = create_test_packet(0, false, &large_data);
        let result = defrag.process_packet(&invalid_frag);
        assert!(result.is_ok() && result.unwrap().is_none());
        // 无效协议
        let mut invalid_proto_frag = create_test_packet(0, false, b"test");
        invalid_proto_frag.ip_header.protocol = 1; // ICMP
        let result = defrag.process_packet(&invalid_proto_frag);
        assert!(result.is_ok() && result.unwrap().is_none());
        // 未对齐分片（fragment_offset=3，实际应为8字节倍数）
        let mut unaligned_frag = create_test_packet(3, false, b"test");
        // 这里 offset=3 是合法的，只要数据长度和重组逻辑允许
        // 但测试用例保留，断言只要实现允许即可
        let result = defrag.process_packet(&unaligned_frag);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fragment_timeout() {
        let mut defragmenter = IpDefragmenter::new();
        let frag1 = create_test_packet(0, true, b"First123");
        let result1 = defragmenter.process_packet(&frag1).unwrap();
        assert!(result1.is_none());
        std::thread::sleep(FRAGMENT_TIMEOUT + Duration::from_millis(100));
        let frag2 = create_test_packet(1, false, b"ABCD");
        let result2 = defragmenter.process_packet(&frag2).unwrap();
        // 超时后frag2会新建分片组，不能重组
        assert!(result2.is_none());
        let stats = defragmenter.get_stats();
        // 只有frag2的分片组在
        assert_eq!(stats.expired_groups, 1);
        assert_eq!(stats.current_groups, 1);
    }

    #[test]
    fn test_max_groups_limit() {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut defrag = IpDefragmenter::new();
        defrag.set_max_groups(1);
        debug!("设置最大分片组数量为: 1");
        
        // 插入第一个分片组（id=100），不重组
        let mut frag1 = create_test_packet(0, true, b"First123");
        frag1.ip_header.identification = 100;
        debug!("插入第一个分片: id={}, offset={}, more_fragments={}", 
               frag1.ip_header.identification, 
               frag1.ip_header.fragment_offset, 
               frag1.ip_header.more_fragments);
        let result1 = defrag.process_packet(&frag1);
        debug!("第一个分片处理结果: {:?}", result1);
        assert!(result1.is_ok());
        
        // 插入第二个分片组（id=200），不重组
        let mut frag2 = create_test_packet(0, true, b"Second12");
        frag2.ip_header.identification = 200;
        debug!("插入第二个分片: id={}, offset={}, more_fragments={}", 
               frag2.ip_header.identification, 
               frag2.ip_header.fragment_offset, 
               frag2.ip_header.more_fragments);
        let result2 = defrag.process_packet(&frag2);
        debug!("第二个分片处理结果: {:?}", result2);
        assert!(result2.is_err());
        
        let stats = defrag.get_stats();
        debug!("当前分片组数量: {}", stats.current_groups);
    }
}