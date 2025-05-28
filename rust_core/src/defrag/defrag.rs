use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::decode::{DecodedPacket, IpHeader};
use std::net::IpAddr;

#[derive(Debug)]
struct IpFragment {
    data: Vec<u8>,
    offset: u16,
    more_fragments: bool,
    received_time: Instant,
}

pub struct IpDefragmenter {
    fragments: HashMap<(IpAddr, IpAddr, u16), Vec<IpFragment>>,
    timeout: Duration,
}

impl IpDefragmenter {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            fragments: HashMap::new(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn process_packet(&mut self, packet: &DecodedPacket) -> Option<DecodedPacket> {
        // 如果不是分片包，直接返回
        if packet.ip_header.fragment_offset == 0 && !packet.ip_header.flags & 0x2000 != 0 {
            return Some(packet.clone());
        }

        let fragment = IpFragment {
            data: packet.payload.clone(),
            offset: packet.ip_header.fragment_offset,
            more_fragments: packet.ip_header.flags & 0x2000 != 0,
            received_time: Instant::now(),
        };

        let key = (
            packet.ip_header.src_ip,
            packet.ip_header.dst_ip, 
            packet.ip_header.identification
        );

        let fragments = self.fragments.entry(key).or_insert_with(Vec::new);
        fragments.push(fragment);

        self.try_reassemble(packet, key)
    }

    fn try_reassemble(&mut self, original: &DecodedPacket, key: (IpAddr, IpAddr, u16)) -> Option<DecodedPacket> {
        let fragments = self.fragments.get(&key)?;
        
        // 检查是否收到了所有分片
        let mut has_last_fragment = false;
        let mut total_len = 0;
        
        for fragment in fragments {
            if !fragment.more_fragments {
                has_last_fragment = true;
                total_len = fragment.offset as usize + fragment.data.len();
            }
            
            if fragment.received_time.elapsed() > self.timeout {
                self.fragments.remove(&key);
                return None;
            }
        }

        if !has_last_fragment {
            return None;
        }

        // 重组分片
        let mut reassembled = vec![0u8; total_len];
        let fragments = self.fragments.get(&key)?;
        
        for fragment in fragments {
            let start = fragment.offset as usize;
            let end = start + fragment.data.len();
            reassembled[start..end].copy_from_slice(&fragment.data);
        }

        // 创建新的完整包
        self.fragments.remove(&key);
        Some(DecodedPacket {
            timestamp: original.timestamp,
            ip_header: IpHeader {
                fragment_offset: 0,
                flags: original.ip_header.flags & !0x2000, // 清除 MF 标志
                total_length: ((original.ip_header.ihl as usize * 4) + total_len) as u16,
                ..original.ip_header.clone()
            },
            src_port: original.src_port,
            dst_port: original.dst_port,
            payload: reassembled,
            protocol: original.protocol.clone(),
        })
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
                flags: if more_fragments { 0x2000 } else { 0 },
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
        let mut defragmenter = IpDefragmenter::new(30);
        
        // 第一个分片
        let packet1 = create_test_packet(0, true, b"First ");
        let result1 = defragmenter.process_packet(&packet1);
        assert!(result1.is_none());

        // 第二个分片
        let packet2 = create_test_packet(6, true, b"fragment ");
        let result2 = defragmenter.process_packet(&packet2);
        assert!(result2.is_none());

        // 最后一个分片
        let packet3 = create_test_packet(14, false, b"test");
        let result3 = defragmenter.process_packet(&packet3);
        
        assert!(result3.is_some());
        let reassembled = result3.unwrap();
        assert_eq!(reassembled.payload, b"First fragment test");
    }
}