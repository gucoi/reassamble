use crate::{
    decode::{decode_packet, TransportProtocol},
    defrag::IpDefragmenter,
    stream::ShardedTcpReassembler,
    SafePacket, Result, ReassembleError,
};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct PacketProcessor {
    defragmenter: Arc<RwLock<IpDefragmenter>>,
    reassembler: Arc<ShardedTcpReassembler>,
}

impl PacketProcessor {
    pub fn new(reassembler: Arc<ShardedTcpReassembler>) -> Self {
        Self {
            defragmenter: Arc::new(RwLock::new(IpDefragmenter::new(10))),
            reassembler,
        }
    }

    pub async fn process_packet(&self, packet: &SafePacket) -> Result<Option<Vec<u8>>> {
        let mut buffer = self.buffer_pool.acquire().await;
        
        // 1. 解码数据包
        let decoded = decode_packet(packet)
            .ok_or(ReassembleError::DecodeError("Failed to decode packet".into()))?;

        // 2. IP 分片重组
        let defrag_result = {
            let mut defragmenter = self.defragmenter.write().await;
            defragmenter.process_packet(&decoded)
        };

        // 3. 处理分片结果
        match defrag_result {
            Some(complete_packet) => {
                match complete_packet.protocol {
                    TransportProtocol::Tcp { .. } => {
                        Ok(self.reassembler.process_packet(&complete_packet).await)
                    }
                    TransportProtocol::Udp => {
                        Ok(Some(complete_packet.payload))
                    }
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use libc::timegm;

    use super::*;
    use crate::ShardConfig;

    fn create_test_tcp_packet() -> SafePacket{
        // Create a simple TCP packet for testing
        SafePacket::new(vec![
            0x45, 0x00, 0x00, 0x28, // IP header
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // TCP header
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00
            ], 
            0
        )
}

    fn create_test_ip_fragments() -> (SafePacket, SafePacket) {
        // First fragment
        let frag1 = SafePacket::new(vec![
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x01, 0x20, 0x00, // Flags=1 (More Fragments)
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // Payload
            0x08, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x03
        ], 0);

        // Second fragment
        let frag2 = SafePacket::new(vec![
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x01, 0x20, 0x08, // Fragment Offset=8
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // Payload
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b
        ], 0);

        (frag1, frag2)
    }

    fn create_test_ip_fragments_three_parts() -> (SafePacket, SafePacket, SafePacket) {
        // First fragment
        let frag1 = SafePacket::new(vec![
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x01, 0x20, 0x00, // Flags=1 (More Fragments)
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // Payload
            0x08, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x03
        ], 0);

        // Second fragment
        let frag2 = SafePacket::new(vec![
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x01, 0x20, 0x08, // Flags=1 (More Fragments)
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // Payload
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b
        ], 0);

        // Third fragment
        let frag3 = SafePacket::new(vec![
            0x45, 0x00, 0x00, 0x20, // IP header
            0x00, 0x00, 0x20, 0x10, // Fragment Offset=16, No More Fragments
            0x40, 0x01, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // Payload
            0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13
        ], 0);

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