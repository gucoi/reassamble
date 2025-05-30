use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::decode::{DecodedPacket, IpHeader};
use std::sync::{Arc, Mutex};
use bytes::BytesMut;
use log::{debug, info, error};

#[derive(Debug)]
struct IpFragment {
    data: BytesMut,
    offset: u16,
    more_fragments: bool,
    received_time: Instant,
}

#[derive(Debug)]
struct FragmentGroup {
    fragments: Vec<IpFragment>,
    first_seen: Instant,    // 记录第一个分片的到达时间
    last_seen: Instant,     // 记录最后一个分片的到达时间
    total_fragments: u16,   // 预期的总分片数
    received_fragments: u16,// 已收到的分片数
}

#[derive(Debug, Default)]
struct DefragStats {
    total_fragments: u64,      // 处理的总分片数
    reassembled_packets: u64,  // 成功重组的包数
    timeout_fragments: u64,    // 超时的分片数
    error_fragments: u64,      // 错误的分片数
    current_groups: usize,     // 当前活跃的分片组数
}

pub struct IpDefragmenter {
    fragments: Mutex<HashMap<(u32, u32, u16), FragmentGroup>>,
    timeout: Duration,
    group_timeout: Duration,  // 分片组整体超时时间
    max_fragments: usize,     // 单个分片组最大分片数
    cleanup_interval: Duration, // 清理间隔
    stats: Mutex<DefragStats>, // 添加统计信息
}

impl IpDefragmenter {
    pub fn new(timeout_secs: u64, group_timeout_secs: u64, max_fragments: usize) -> Self {
        Self {
            fragments: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(timeout_secs),
            group_timeout: Duration::from_secs(group_timeout_secs),
            max_fragments,
            cleanup_interval: Duration::from_secs(1), // 每秒清理一次
            stats: Mutex::new(DefragStats::default()),
        }
    }

    // 启动定期清理任务
    pub async fn start_cleanup_task(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.cleanup_interval);
        loop {
            interval.tick().await;
            self.cleanup_expired_fragments();
        }
    }

    // 清理超时分片
    fn cleanup_expired_fragments(&self) {
        let now = Instant::now();
        let mut expired_keys = Vec::new();
        let mut fragments = self.fragments.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();

        for (key, group) in fragments.iter() {
            // 检查分片组是否整体超时
            if now.duration_since(group.first_seen) > self.group_timeout {
                expired_keys.push(key.clone());
                stats.timeout_fragments += group.fragments.len() as u64;
                continue;
            }

            // 检查是否有分片超时
            let mut has_expired = false;
            for fragment in &group.fragments {
                if now.duration_since(fragment.received_time) > self.timeout {
                    has_expired = true;
                    stats.timeout_fragments += 1;
                    break;
                }
            }

            if has_expired {
                expired_keys.push(key.clone());
            }
        }
        // 移除超时的分片组
        for key in expired_keys {
            fragments.remove(&key);
        }
        // 更新当前活跃的分片组数
        stats.current_groups = fragments.len();
    }

    pub fn process_packet(&mut self, packet: &DecodedPacket) -> Option<DecodedPacket> {
        let mut stats = self.stats.lock().unwrap();
        stats.total_fragments += 1;
        drop(stats);

        debug!("[defrag] process_packet: fragment_offset={}, flags=0x{:x}, payload_len={}, src_ip={}, dst_ip={}", 
            packet.ip_header.fragment_offset, 
            packet.ip_header.flags, 
            packet.payload.len(), 
            packet.ip_header.source_ip, 
            packet.ip_header.dest_ip
        );

        // 如果不是分片包，直接返回
        if packet.ip_header.fragment_offset == 0 && (packet.ip_header.flags & 0x20) == 0 {
            debug!("[defrag] not a fragment, return Some");
            return Some(packet.clone());
        }

        let now = Instant::now();
        let key = (
            packet.ip_header.source_ip,
            packet.ip_header.dest_ip,
            packet.ip_header.identification
        );

        let mut fragments = self.fragments.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();
        // 获取或创建分片组
        let group = fragments.entry(key).or_insert_with(|| {
            // 计算预期的总分片数
            let total_fragments = if (packet.ip_header.flags & 0x20) == 0 {
                // 如果是最后一个分片，根据偏移量计算总分片数
                (packet.ip_header.fragment_offset as usize + packet.payload.len() + 7) / 8
            } else {
                // 如果不是最后一个分片，暂时设置为0，等待最后一个分片
                0
            };
            
            FragmentGroup {
                fragments: Vec::new(),
                first_seen: now,
                last_seen: now,
                total_fragments: total_fragments as u16,
                received_fragments: 0,
            }
        });

        // 更新分片组信息
        group.last_seen = now;
        group.received_fragments += 1;

        // 如果是最后一个分片，更新总分片数
        if (packet.ip_header.flags & 0x20) == 0 {
            let total_fragments = (packet.ip_header.fragment_offset as usize + packet.payload.len() + 7) / 8;
            group.total_fragments = total_fragments as u16;
        }

        debug!("[defrag] group now has {} fragments, total expected: {}", group.fragments.len() + 1, group.total_fragments);

        // 检查分片组是否超时
        if now.duration_since(group.first_seen) > self.group_timeout {
            info!("[defrag] group timeout, remove group");
            stats.timeout_fragments += group.fragments.len() as u64;
            fragments.remove(&key);
            return None;
        }

        // 检查分片数量限制
        if group.fragments.len() >= self.max_fragments {
            error!("[defrag] too many fragments, drop");
            stats.error_fragments += 1;
            return None;
        }

        // 添加新分片
        let fragment = IpFragment {
            data: packet.payload.clone(),
            offset: packet.ip_header.fragment_offset,
            more_fragments: packet.ip_header.flags & 0x20 != 0,
            received_time: now,
        };

        group.fragments.push(fragment);
        group.fragments.sort_by_key(|f| f.offset);
        debug!("[defrag] fragments after push: offsets={:?}", group.fragments.iter().map(|f| f.offset).collect::<Vec<_>>());

        // 更新当前活跃的分片组数
        stats.current_groups = fragments.len();

        // 尝试重组
        drop(fragments);
        drop(stats);
        self.try_reassemble(packet, key)
    }

    fn try_reassemble(&mut self, original: &DecodedPacket, key: (u32, u32, u16)) -> Option<DecodedPacket> {
        let mut stats = self.stats.lock().unwrap();
        debug!("[defrag] try_reassemble: key=({},{},{})", key.0, key.1, key.2);
        let mut fragments = self.fragments.lock().unwrap();
        let group = fragments.get(&key)?;
        let now = Instant::now();
        debug!("[defrag] try_reassemble: group.fragments.len()={}, total_fragments={}", group.fragments.len(), group.total_fragments);

        // 检查分片组是否超时
        if now.duration_since(group.first_seen) > self.group_timeout {
            info!("[defrag] try_reassemble: group timeout");
            stats.timeout_fragments += group.fragments.len() as u64;
            fragments.remove(&key);
            return None;
        }

        // 检查是否收到了所有分片
        if group.received_fragments < group.total_fragments {
            debug!("[defrag] try_reassemble: waiting for more fragments: received={}, total={}", group.received_fragments, group.total_fragments);
            return None;
        }

        let mut has_last_fragment = false;
        let mut total_len = 0;
        let mut gaps = Vec::new();
        let mut prev_end = 0;

        for (i, fragment) in group.fragments.iter().enumerate() {
            debug!("[defrag] fragment[{}]: offset={}, len={}, more_fragments={}", i, fragment.offset, fragment.data.len(), fragment.more_fragments);
            // 检查分片是否超时
            if now.duration_since(fragment.received_time) > self.timeout {
                info!("[defrag] try_reassemble: fragment timeout");
                stats.timeout_fragments += 1;
                fragments.remove(&key);
                return None;
            }

            // 检查分片是否连续
            if fragment.offset as usize > prev_end {
                debug!("[defrag] try_reassemble: gap detected: prev_end={}, offset={}", prev_end, fragment.offset);
                gaps.push((prev_end, fragment.offset as usize));
            }

            if !fragment.more_fragments {
                has_last_fragment = true;
                total_len = fragment.offset as usize + fragment.data.len();
                debug!("[defrag] try_reassemble: found last fragment, total_len={}", total_len);
            }

            prev_end = fragment.offset as usize + fragment.data.len();
        }

        // 如果没有收到最后一个分片，或者存在间隙，则继续等待
        if !has_last_fragment {
            error!("[defrag] try_reassemble: no last fragment");
            stats.error_fragments += 1;
            return None;
        }
        if !gaps.is_empty() {
            error!("[defrag] try_reassemble: gaps exist: {:?}", gaps);
            stats.error_fragments += 1;
            return None;
        }

        // 重组分片
        let mut reassembled = vec![0u8; total_len];
        for (i, fragment) in group.fragments.iter().enumerate() {
            let start = fragment.offset as usize;
            let end = start + fragment.data.len();
            if end > reassembled.len() {
                error!("[defrag] try_reassemble: fragment out of bounds: start={}, end={}, reassembled.len={}", start, end, reassembled.len());
                stats.error_fragments += 1;
                return None; // 分片越界
            }
            debug!("[defrag] try_reassemble: copy fragment[{}] to reassembled[{}..{}]", i, start, end);
            reassembled[start..end].copy_from_slice(&fragment.data);
        }

        // 重组成功，移除分片组
        info!("[defrag] try_reassemble: reassembly success, remove group");
        stats.reassembled_packets += 1;
        fragments.remove(&key);
        // 更新当前活跃的分片组数
        stats.current_groups = fragments.len();
        Some(DecodedPacket {
            timestamp: original.timestamp,
            ip_header: IpHeader {
                version: 4,
                ihl: 5,
                tos: 0,
                total_length: ((original.ip_header.ihl as usize * 4) + total_len) as u16,
                identification: original.ip_header.identification,
                flags: original.ip_header.flags & !0x20,
                fragment_offset: 0,
                ttl: 64,
                protocol: original.ip_header.protocol,
                header_checksum: 0,
                source_ip: original.ip_header.source_ip,
                dest_ip: original.ip_header.dest_ip,
            },
            src_port: original.src_port,
            dst_port: original.dst_port,
            payload: BytesMut::from(&reassembled[..]),
            protocol: original.protocol.clone(),
        })
    }

    pub fn get_stats(&self) -> DefragStats {
        let fragments = self.fragments.lock().unwrap();
        let stats = self.stats.lock().unwrap();
        DefragStats {
            total_fragments: stats.total_fragments,
            reassembled_packets: stats.reassembled_packets,
            timeout_fragments: stats.timeout_fragments,
            error_fragments: stats.error_fragments,
            current_groups: stats.current_groups,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::TransportProtocol;

    fn create_test_packet(offset: u16, more_fragments: bool, data: &[u8]) -> DecodedPacket {
        DecodedPacket {
            timestamp: 0,
            ip_header: IpHeader {
                version: 4,
                ihl: 5,
                tos: 0,
                total_length: (20 + data.len()) as u16,
                identification: 1234,
                flags: if more_fragments { 0x20 } else { 0 },
                fragment_offset: offset,
                ttl: 64,
                protocol: 6,
                header_checksum: 0,
                source_ip: u32::from_be_bytes([192,168,1,1]),
                dest_ip: u32::from_be_bytes([192,168,1,2]),
            },
            src_port: 1234,
            dst_port: 80,
            payload: BytesMut::from(data),
            protocol: TransportProtocol::TCP {
                seq: 0,
                ack: 0,
                flags: 0,
                window: 0,
            },
        }
    }

    #[test]
    fn test_ip_defragmentation() {
        let mut defragmenter = IpDefragmenter::new(30, 60, 10);
        
        // 第一个分片
        let packet1 = create_test_packet(0, true, b"First ");
        let result1 = defragmenter.process_packet(&packet1);
        assert!(result1.is_none());

        // 第二个分片
        let packet2 = create_test_packet(6, true, b"fragment ");
        let result2 = defragmenter.process_packet(&packet2);
        assert!(result2.is_none());

        // 最后一个分片
        let packet3 = create_test_packet(15, false, b"test");
        let result3 = defragmenter.process_packet(&packet3);
        
        assert!(result3.is_some());
        let reassembled = result3.unwrap();
        assert_eq!(&reassembled.payload[..], b"First fragment test");
    }
}