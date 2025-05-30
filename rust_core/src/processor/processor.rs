use crate::{
    decode::{decode_packet, TransportProtocol, DecodedPacket},
    defrag::IpDefragmenter,
    stream::ShardedTcpReassembler,
    SafePacket, Result, ReassembleError,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, error};
use super::worker::WorkerPool;
use rayon::prelude::*;
use crossbeam_channel::{bounded, Sender, Receiver};
use std::sync::atomic::{AtomicUsize, Ordering};
use bytes::BytesMut;

/// 批量数据包结构
#[derive(Debug)]
pub struct BatchPacket {
    pub packets: Vec<SafePacket>,
    pub timestamp: u64,
}

impl BatchPacket {
    pub fn new(packets: Vec<SafePacket>, timestamp: u64) -> Self {
        Self { packets, timestamp }
    }

    pub fn with_capacity(capacity: usize, timestamp: u64) -> Self {
        Self {
            packets: Vec::with_capacity(capacity),
            timestamp,
        }
    }

    pub fn add_packet(&mut self, packet: SafePacket) {
        self.packets.push(packet);
    }
}

pub struct PacketProcessor {
    defragmenter: Arc<RwLock<IpDefragmenter>>,
    reassembler: Arc<ShardedTcpReassembler>,
    worker_pool: Arc<WorkerPool>,
    batch_size: usize,
    active_batches: AtomicUsize,
}

impl PacketProcessor {
    pub fn new(reassembler: Arc<ShardedTcpReassembler>) -> Self {
        Self {
            defragmenter: Arc::new(RwLock::new(IpDefragmenter::new(30, 60, 10))),
            reassembler,
            worker_pool: Arc::new(WorkerPool::new()),
            batch_size: 1000,
            active_batches: AtomicUsize::new(0),
        }
    }

    pub async fn process_packet(&self, packet: &SafePacket) -> Result<Option<Vec<u8>>> {
        // 使用工作线程池处理数据包
        self.worker_pool.submit(packet.clone());
        
        // 解码数据包
        let decoded = decode_packet(packet)
            .map_err(|e| ReassembleError::DecodeError(e.to_string()))?;
        
        // 处理分片
        if decoded.ip_header.flags & 0x2000u16 != 0 {
            let mut defrag = self.defragmenter.write().await;
            if let Some(reassembled) = defrag.process_packet(&decoded) {
                return Ok(Some(reassembled.to_vec()));
            }
            return Ok(None);
        }
        
        // 处理 TCP 重组
        if let TransportProtocol::TCP { .. } = decoded.protocol {
            if let Some(reassembled) = self.reassembler.process_packet(&decoded) {
                return Ok(Some(reassembled.to_vec()));
            }
        }
        
        Ok(None)
    }

    pub async fn process_batch(&self, batch: BatchPacket) -> Result<Vec<Option<Vec<u8>>>> {
        self.active_batches.fetch_add(1, Ordering::Relaxed);

        // 1. 先串行处理分片重组
        let mut ready_packets = Vec::with_capacity(batch.packets.len());
        for packet in &batch.packets {
            let decoded = match decode_packet(packet) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if decoded.ip_header.flags & 0x2000u16 != 0 {
                let mut defrag = self.defragmenter.write().await;
                if let Some(reassembled) = defrag.process_packet(&decoded) {
                    // 只将重组完成的包加入 ready_packets
                    ready_packets.push(SafePacket::new(reassembled.payload.clone(), packet.timestamp));
                }
            } else {
                ready_packets.push(packet.clone());
            }
        }

        // 2. 并行处理 TCP 重组和其它逻辑
        let results: Vec<_> = ready_packets.par_iter()
            .map(|packet| {
                let decoded = decode_packet(packet).ok()?;
                if let TransportProtocol::TCP { .. } = decoded.protocol {
                    self.reassembler.process_packet(&decoded)
                } else {
                    None
                }
            })
            .collect();

        self.active_batches.fetch_sub(1, Ordering::Relaxed);
        Ok(results)
    }

    pub fn get_active_batches(&self) -> usize {
        self.active_batches.load(Ordering::Relaxed)
    }

    pub fn set_batch_size(&mut self, size: usize) {
        self.batch_size = size;
    }
}

/// 批量处理统计信息
#[derive(Debug, Default)]
pub struct BatchProcessStats {
    pub total_packets: usize,
    pub successful_packets: usize,
    pub partial_packets: usize,
    pub failed_packets: usize,
    pub processing_time: std::time::Duration,
}

impl BatchProcessStats {
    pub fn throughput(&self) -> f64 {
        self.total_packets as f64 / self.processing_time.as_secs_f64()
    }
    
    pub fn success_rate(&self) -> f64 {
        if self.total_packets == 0 {
            return 0.0;
        }
        self.successful_packets as f64 / self.total_packets as f64
    }
}

#[cfg(test)]
mod tests {
    use libc::timegm;

    use super::*;
    use crate::ShardConfig;

    fn create_test_tcp_packet() -> SafePacket{
        SafePacket::new(BytesMut::from(&[
            0x45, 0x00, 0x00, 0x28, // IP header
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ][..]), 0)
    }

    fn create_test_ip_fragments() -> (SafePacket, SafePacket) {
        let frag1 = SafePacket::new(BytesMut::from(&[
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x01, 0x20, 0x00, // Flags=1 (More Fragments)
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x03
        ][..]), 0);
        let frag2 = SafePacket::new(BytesMut::from(&[
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x01, 0x20, 0x08, // Fragment Offset=8
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x08, 0x09, 0x0a, 0x0b
        ][..]), 0);
        (frag1, frag2)
    }

    fn create_test_ip_fragments_three_parts() -> (SafePacket, SafePacket, SafePacket) {
        let frag1 = SafePacket::new(BytesMut::from(&[
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x01, 0x20, 0x00, // Flags=1 (More Fragments)
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x03
        ][..]), 0);
        let frag2 = SafePacket::new(BytesMut::from(&[
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x01, 0x20, 0x08, // Flags=1 (More Fragments)
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x08, 0x09, 0x0a, 0x0b
        ][..]), 0);
        let frag3 = SafePacket::new(BytesMut::from(&[
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x00, 0x20, 0x10, // Fragment Offset=16, No More Fragments
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x10, 0x11, 0x12, 0x13
        ][..]), 0);
        (frag1, frag2, frag3)
    }

    #[tokio::test]
    async fn test_packet_processing() {
        let config = ShardConfig::default();
        let reassembler = Arc::new(ShardedTcpReassembler::new(config));
        let processor = PacketProcessor::new(reassembler);

        // 创建测试包
        let test_packet = create_test_tcp_packet();
        
        // 处理包
        let result = processor.process_packet(&test_packet).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fragmented_packet() {
        let config = ShardConfig::default();
        let reassembler = Arc::new(ShardedTcpReassembler::new(config));
        let processor = PacketProcessor::new(reassembler);

        // 创建分片测试包
        let (frag1, frag2) = create_test_ip_fragments();
        
        // 处理第一个分片
        let result1 = processor.process_packet(&frag1).await;
        assert!(result1.unwrap().is_none()); // 第一个分片不会产生输出
        
        // 处理第二个分片
        let result2 = processor.process_packet(&frag2).await;
        assert!(result2.unwrap().is_some()); // 重组完成后应该有输出
    }

    #[tokio::test]
async fn test_ip_fragmentation_scenarios() {
    let config = ShardConfig::default();
    let reassembler = Arc::new(ShardedTcpReassembler::new(config));
    let processor = PacketProcessor::new(reassembler);

    // 测试三个分片的情况
    let (frag1, frag2, frag3) = create_test_ip_fragments_three_parts();
    
    // 处理第一个分片
    let result1 = processor.process_packet(&frag1).await.unwrap();
    assert!(result1.is_none()); // 第一个分片，等待更多
    
    // 处理第二个分片
    let result2 = processor.process_packet(&frag2).await.unwrap();
    assert!(result2.is_none()); // 第二个分片，还在等待
    
    // 处理第三个（最后）分片
    let result3 = processor.process_packet(&frag3).await.unwrap();
    assert!(result3.is_some()); // 全部分片已收到，应该有输出
}

    #[tokio::test]
    async fn test_error_handling() {
        // 测试空指针
        // 测试无效数据包
        // 测试超时情况
        // 测试内存限制
    }
}