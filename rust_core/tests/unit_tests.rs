#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use rust_core::SafePacket;
    use rust_core::decode::{IpHeader, TransportProtocol, DecodedPacket};

    // 辅助函数：创建简单的测试数据包
    fn create_test_packet() -> SafePacket {
        let mut data = BytesMut::with_capacity(42);
        
        // 以太网头部 (14 bytes)
        data.extend_from_slice(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // 目的MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  // 源MAC
            0x08, 0x00,                           // IPv4类型
        ]);
        
        // IPv4头部 (20 bytes)
        data.extend_from_slice(&[
            0x45, 0x00,                           // 版本(4)和头长度(5*4=20)
            0x00, 0x1c,                           // 总长度 (28 bytes = 20 + 8 字节)
            0x00, 0x01,                           // 标识
            0x00, 0x00,                           // 标志和片偏移
            0x40, 0x06,                           // TTL和协议(TCP=6)
            0x00, 0x00,                           // 头部校验和
            0xc0, 0xa8, 0x00, 0x01,               // 源IP (192.168.0.1)
            0xc0, 0xa8, 0x00, 0x02,               // 目的IP (192.168.0.2)
        ]);
        
        // TCP头部 (8 bytes) - 简化的头部
        data.extend_from_slice(&[
            0x04, 0xd2, 0x00, 0x50,               // 源端口(1234), 目的端口(80)
            0x00, 0x00, 0x00, 0x00,               // 序列号
        ]);
        
        SafePacket::new(data, 12345678)
    }
    
    // 单元测试：测试SafePacket功能
    #[test]
    fn test_safe_packet() {
        let data = BytesMut::from(&b"Test packet data"[..]);
        let timestamp = 12345678;
        
        let packet = SafePacket::new(data.clone(), timestamp);
        
        assert_eq!(packet.data.len(), data.len());
        assert_eq!(packet.timestamp, timestamp);
        
        // 测试克隆
        let cloned = packet.clone();
        assert_eq!(cloned.data.len(), packet.data.len());
        assert_eq!(cloned.timestamp, packet.timestamp);
        
        // 测试从字节切片创建
        let from_bytes = SafePacket::from_bytes(b"Another test", 87654321);
        assert_eq!(from_bytes.data.len(), 12);
        assert_eq!(from_bytes.timestamp, 87654321);
    }
    
    // 单元测试：测试结构体创建
    #[test]
    fn test_struct_creation() {
        // 手动创建一个IP头部
        let ip_header = IpHeader {
            version: 4,
            ihl: 5,
            tos: 0,
            total_length: 60,
            identification: 1234,
            flags: 0,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 64,
            protocol: 6, // TCP
            header_checksum: 0,
            source_ip: 0xc0a80001, // 192.168.0.1
            dest_ip: 0xc0a80002,   // 192.168.0.2
        };
        
        // 验证IP头部
        assert_eq!(ip_header.version, 4);
        assert_eq!(ip_header.protocol, 6);
        assert_eq!(ip_header.source_ip, 0xc0a80001);
        assert_eq!(ip_header.dest_ip, 0xc0a80002);
        
        // 测试测试数据包
        let test_packet = create_test_packet();
        assert!(test_packet.data.len() > 0);
        assert_eq!(test_packet.timestamp, 12345678);
    }
} 