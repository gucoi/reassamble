use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::decode::{DecodedPacket, IpHeader};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct IpFragment {
    data: Vec<u8>,
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
    total_fragments: u64,
    reassembled_packets: u64,
    timeout_fragments: u64,
    error_fragments: u64,
    current_groups: usize,
}

pub struct IpDefragmenter {
    fragments: Mutex<HashMap<(IpAddr, IpAddr, u16), FragmentGroup>>,
    timeout: Duration,
    group_timeout: Duration,  // 分片组整体超时时间
    max_fragments: usize,     // 单个分片组最大分片数
    cleanup_interval: Duration, // 清理间隔
}

impl IpDefragmenter {
    pub fn new(timeout_secs: u64, group_timeout_secs: u64, max_fragments: usize) -> Self {
        Self {
            fragments: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(timeout_secs),
            group_timeout: Duration::from_secs(group_timeout_secs),
            max_fragments,
            cleanup_interval: Duration::from_secs(1), // 每秒清理一次
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

        for (key, group) in fragments.iter() {
            // 检查分片组是否整体超时
            if now.duration_since(group.first_seen) > self.group_timeout {
                expired_keys.push(key.clone());
                continue;
            }

            // 检查是否有分片超时
            let mut has_expired = false;
            for fragment in &group.fragments {
                if now.duration_since(fragment.received_time) > self.timeout {
                    has_expired = true;
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
    }

    pub fn process_packet(&mut self, packet: &DecodedPacket) -> Option<DecodedPacket> {
        println!("[defrag] process_packet: fragment_offset={}, flags=0x{:x}, payload_len={}", packet.ip_header.fragment_offset, packet.ip_header.flags, packet.payload.len());
        // 如果不是分片包，直接返回
        if packet.ip_header.fragment_offset == 0 && (packet.ip_header.flags & 0x20) == 0 {
            println!("[defrag] not a fragment, return Some");
            return Some(packet.clone());
        }

        let now = Instant::now();
        let key = (
            packet.ip_header.src_ip,
            packet.ip_header.dst_ip, 
            packet.ip_header.identification
        );

        let mut fragments = self.fragments.lock().unwrap();
        // 获取或创建分片组
        let group = fragments.entry(key).or_insert_with(|| FragmentGroup {
            fragments: Vec::new(),
            first_seen: now,
            last_seen: now,
            total_fragments: 0,
            received_fragments: 0,
        });

        // 更新分片组信息
        group.last_seen = now;
        group.received_fragments += 1;
        println!("[defrag] group now has {} fragments", group.fragments.len() + 1);

        // 检查分片组是否超时
        if now.duration_since(group.first_seen) > self.group_timeout {
            println!("[defrag] group timeout, remove group");
            fragments.remove(&key);
            return None;
        }

        // 检查分片数量限制
        if group.fragments.len() >= self.max_fragments {
            println!("[defrag] too many fragments, drop");
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
        println!("[defrag] fragments after push: offsets={:?}", group.fragments.iter().map(|f| f.offset).collect::<Vec<_>>());

        // 尝试重组
        drop(fragments); // 显式释放锁
        self.try_reassemble(packet, key)
    }

    fn try_reassemble(&mut self, original: &DecodedPacket, key: (IpAddr, IpAddr, u16)) -> Option<DecodedPacket> {
        println!("[defrag] try_reassemble: key={:?}", key);
        let mut fragments = self.fragments.lock().unwrap();
        let group = fragments.get(&key)?;
        let now = Instant::now();
        println!("[defrag] try_reassemble: group.fragments.len()={}", group.fragments.len());

        // 检查分片组是否超时
        if now.duration_since(group.first_seen) > self.group_timeout {
            println!("[defrag] try_reassemble: group timeout");
            fragments.remove(&key);
            return None;
        }

        // 检查是否收到了所有分片
        let mut has_last_fragment = false;
        let mut total_len = 0;
        let mut gaps = Vec::new();
        let mut prev_end = 0;

        for (i, fragment) in group.fragments.iter().enumerate() {
            println!("[defrag] fragment[{}]: offset={}, len={}, more_fragments={}", i, fragment.offset, fragment.data.len(), fragment.more_fragments);
            // 检查分片是否超时
            if now.duration_since(fragment.received_time) > self.timeout {
                println!("[defrag] try_reassemble: fragment timeout");
                fragments.remove(&key);
                return None;
            }

            // 检查分片是否连续
            if fragment.offset as usize > prev_end {
                println!("[defrag] try_reassemble: gap detected: prev_end={}, offset={}", prev_end, fragment.offset);
                gaps.push((prev_end, fragment.offset as usize));
            }

            if !fragment.more_fragments {
                has_last_fragment = true;
                total_len = fragment.offset as usize + fragment.data.len();
                println!("[defrag] try_reassemble: found last fragment, total_len={}", total_len);
            }

            prev_end = fragment.offset as usize + fragment.data.len();
        }

        // 如果没有收到最后一个分片，或者存在间隙，则继续等待
        if !has_last_fragment {
            println!("[defrag] try_reassemble: no last fragment");
            return None;
        }
        if !gaps.is_empty() {
            println!("[defrag] try_reassemble: gaps exist: {:?}", gaps);
            return None;
        }

        // 重组分片
        let mut reassembled = vec![0u8; total_len];
        for (i, fragment) in group.fragments.iter().enumerate() {
            let start = fragment.offset as usize;
            let end = start + fragment.data.len();
            if end > reassembled.len() {
                println!("[defrag] try_reassemble: fragment out of bounds: start={}, end={}, reassembled.len={}", start, end, reassembled.len());
                return None; // 分片越界
            }
            println!("[defrag] try_reassemble: copy fragment[{}] to reassembled[{}..{}]", i, start, end);
            reassembled[start..end].copy_from_slice(&fragment.data);
        }

        // 重组成功，移除分片组
        println!("[defrag] try_reassemble: reassembly success, remove group");
        fragments.remove(&key);
        Some(DecodedPacket {
            timestamp: original.timestamp,
            ip_header: IpHeader {
                fragment_offset: 0,
                flags: original.ip_header.flags & !0x20,
                total_length: ((original.ip_header.ihl as usize * 4) + total_len) as u16,
                ..original.ip_header.clone()
            },
            src_port: original.src_port,
            dst_port: original.dst_port,
            payload: reassembled,
            protocol: original.protocol.clone(),
        })
    }

    pub fn get_stats(&self) -> DefragStats {
        let mut stats = DefragStats::default();
        let fragments = self.fragments.lock().unwrap();
        stats.current_groups = fragments.len();
        // ... 统计其他指标
        stats
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
                total_length: (20 + data.len()) as u16,
                identification: 1,
                flags: if more_fragments { 0x20 } else { 0 },
                fragment_offset: offset,
                ttl: 64,
                protocol: 6,
                checksum: 0,
                src_ip: "192.168.1.1".parse().unwrap(),
                dst_ip: "192.168.1.2".parse().unwrap(),
            },
            src_port: 1234,
            dst_port: 80,
            payload: data.to_vec(),
            protocol: TransportProtocol::Tcp {
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
        assert_eq!(reassembled.payload, b"First fragment test");
    }
}