use std::net::IpAddr;
use crate::SafePacket;
use super::error::{DecodeError, DecodeResult, IpHeaderError, TcpHeaderError, UdpHeaderError, BufferError};

/// IP头部结构
#[derive(Debug, Clone)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}

/// 传输层协议类型
#[derive(Debug, Clone)]
pub enum TransportProtocol {
    /// TCP协议
    Tcp {
        /// 序列号
        seq: u32,
        /// 确认号
        ack: u32,
        /// TCP标志位
        flags: u8,
        /// 窗口大小
        window: u16,
    },
    /// UDP协议
    Udp,
    /// 其他协议
    Other(u8),
}

/// 解码后的数据包结构
#[derive(Debug, Clone)]
pub struct DecodedPacket {
    /// 时间戳
    pub timestamp: u64,
    /// IP头部
    pub ip_header: IpHeader,
    /// 源端口
    pub src_port: u16,
    /// 目标端口
    pub dst_port: u16,
    /// 负载数据
    pub payload: Vec<u8>,
    /// 传输层协议信息
    pub protocol: TransportProtocol,
}

/// 解码IP头部
/// 
/// # Arguments
/// 
/// * `data` - 包含IP头部的数据切片
/// 
/// # Returns
/// 
/// 如果解码成功，返回 Ok(IpHeader)，否则返回 DecodeError
pub fn decode_ip_header(data: &[u8]) -> DecodeResult<IpHeader> {
    // 检查最小长度
    if data.len() < 20 {
        return Err(DecodeError::InsufficientLength {
            required: 20,
            actual: data.len(),
        });
    }

    // 检查版本和IHL
    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        return Err(IpHeaderError::InvalidVersion { version }.into());
    }

    let ihl = data[0] & 0xF;
    if ihl < 5 {
        return Err(IpHeaderError::InvalidIHL { ihl }.into());
    }

    // 检查总长度
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    if total_length < 20 || total_length > data.len() as u16 {
        return Err(IpHeaderError::InvalidTotalLength { length: total_length }.into());
    }

    // 解析IP地址
    let src_ip = IpAddr::V4(std::net::Ipv4Addr::from([
        data[12], data[13], data[14], data[15]
    ]));
    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::from([
        data[16], data[17], data[18], data[19]
    ]));

    // 验证IP地址
    if src_ip.is_unspecified() {
        return Err(IpHeaderError::InvalidSourceIp { ip: src_ip }.into());
    }
    if dst_ip.is_unspecified() {
        return Err(IpHeaderError::InvalidDestinationIp { ip: dst_ip }.into());
    }

    Ok(IpHeader {
        version,
        ihl,
        total_length,
        identification: u16::from_be_bytes([data[4], data[5]]),
        flags: (data[6] >> 5) & 0x7,
        fragment_offset: ((data[6] as u16 & 0x1F) << 8) | data[7] as u16,
        ttl: data[8],
        protocol: data[9],
        checksum: u16::from_be_bytes([data[10], data[11]]),
        src_ip,
        dst_ip,
    })
}

/// 解码数据包
/// 
/// # Arguments
/// 
/// * `packet` - 要解码的数据包
/// 
/// # Returns
/// 
/// 如果解码成功，返回 Ok(DecodedPacket)，否则返回 DecodeError
pub fn decode_packet(packet: &SafePacket) -> DecodeResult<DecodedPacket> {
    // 检查数据包是否为空
    if packet.data.is_empty() {
        return Err(DecodeError::EmptyPacket);
    }

    // 验证最小包大小
    const MIN_PACKET_SIZE: usize = 34; // 以太网(14) + IP(20)
    if packet.data.len() < MIN_PACKET_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_PACKET_SIZE,
            actual: packet.data.len(),
        });
    }

    // 解码IP头部
    let ip_header = decode_ip_header(&packet.data[14..])
        .map_err(|e| e.with_context("解码IP头部失败"))?;

    // 根据协议类型解码
    match ip_header.protocol {
        6 => decode_tcp_packet(packet, &ip_header)
            .map_err(|e| e.with_context("解码TCP包失败")),
        17 => decode_udp_packet(packet, &ip_header)
            .map_err(|e| e.with_context("解码UDP包失败")),
        protocol => Ok(DecodedPacket {
            timestamp: packet.timestamp,
            ip_header,
            src_port: 0,
            dst_port: 0,
            payload: Vec::new(),
            protocol: TransportProtocol::Other(protocol),
        }),
    }
}

/// 使用预分配缓冲区解码数据包
/// 
/// # Arguments
/// 
/// * `packet` - 要解码的数据包
/// * `buffer` - 预分配的缓冲区，用于存储解码后的数据
/// 
/// # Returns
/// 
/// 如果解码成功，返回 Ok(DecodedPacket)，否则返回 DecodeError
pub fn decode_packet_with_buffer(packet: &SafePacket, buffer: &mut Vec<u8>) -> DecodeResult<DecodedPacket> {
    // 检查数据包是否为空
    if packet.data.is_empty() {
        return Err(DecodeError::EmptyPacket);
    }

    // 检查缓冲区容量
    if buffer.capacity() < packet.data.len() {
        return Err(BufferError::InsufficientCapacity {
            required: packet.data.len(),
            actual: buffer.capacity(),
        }.into());
    }
    
    // 清空缓冲区并复制数据
    buffer.clear();
    buffer.extend_from_slice(&packet.data);

    // 验证最小包大小
    const MIN_PACKET_SIZE: usize = 34; // 以太网(14) + IP(20)
    if buffer.len() < MIN_PACKET_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_PACKET_SIZE,
            actual: buffer.len(),
        });
    }

    // 解码IP头部
    let ip_header = decode_ip_header(&buffer[14..])
        .map_err(|e| e.with_context("解码IP头部失败"))?;

    // 根据协议类型解码
    match ip_header.protocol {
        6 => decode_tcp_packet_with_buffer(packet, buffer, &ip_header)
            .map_err(|e| e.with_context("解码TCP包失败")),
        17 => decode_udp_packet_with_buffer(packet, buffer, &ip_header)
            .map_err(|e| e.with_context("解码UDP包失败")),
        protocol => Ok(DecodedPacket {
            timestamp: packet.timestamp,
            ip_header,
            src_port: 0,
            dst_port: 0,
            payload: Vec::new(),
            protocol: TransportProtocol::Other(protocol),
        }),
    }
}

/// 解码TCP包
fn decode_tcp_packet(packet: &SafePacket, ip_header: &IpHeader) -> DecodeResult<DecodedPacket> {
    const MIN_TCP_SIZE: usize = 54; // 以太网(14) + IP(20) + TCP(20)
    if packet.data.len() < MIN_TCP_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_TCP_SIZE,
            actual: packet.data.len(),
        });
    }

    let ip_header_len = (ip_header.ihl * 4) as usize;
    let tcp_offset = 14 + ip_header_len;

    // 获取TCP头部长度
    let tcp_header_len = ((packet.data[tcp_offset + 12] >> 4) & 0xF) * 4;
    if tcp_header_len < 20 {
        return Err(TcpHeaderError::InvalidHeaderLength { length: tcp_header_len }.into());
    }

    let payload_offset = tcp_offset + tcp_header_len as usize;
    if payload_offset > packet.data.len() {
        return Err(DecodeError::InsufficientLength {
            required: payload_offset,
            actual: packet.data.len(),
        });
    }

    // 验证端口号
    let src_port = u16::from_be_bytes([packet.data[tcp_offset], packet.data[tcp_offset + 1]]);
    let dst_port = u16::from_be_bytes([packet.data[tcp_offset + 2], packet.data[tcp_offset + 3]]);
    if src_port == 0 || dst_port == 0 {
        return Err(TcpHeaderError::InvalidPort { port: if src_port == 0 { src_port } else { dst_port } }.into());
    }

    // 验证TCP标志
    let flags = packet.data[tcp_offset + 13];
    if flags & 0x3F == 0 {
        return Err(TcpHeaderError::InvalidFlags { flags }.into());
    }

    // 提取负载
    let payload = packet.data[payload_offset..].to_vec();

    Ok(DecodedPacket {
        timestamp: packet.timestamp,
        ip_header: ip_header.clone(),
        src_port,
        dst_port,
        payload,
        protocol: TransportProtocol::Tcp {
            seq: u32::from_be_bytes([
                packet.data[tcp_offset + 4],
                packet.data[tcp_offset + 5],
                packet.data[tcp_offset + 6],
                packet.data[tcp_offset + 7],
            ]),
            ack: u32::from_be_bytes([
                packet.data[tcp_offset + 8],
                packet.data[tcp_offset + 9],
                packet.data[tcp_offset + 10],
                packet.data[tcp_offset + 11],
            ]),
            flags,
            window: u16::from_be_bytes([packet.data[tcp_offset + 14], packet.data[tcp_offset + 15]]),
        },
    })
}

/// 使用缓冲区解码TCP包
fn decode_tcp_packet_with_buffer(
    packet: &SafePacket,
    buffer: &[u8],
    ip_header: &IpHeader,
) -> DecodeResult<DecodedPacket> {
    const MIN_TCP_SIZE: usize = 54; // 以太网(14) + IP(20) + TCP(20)
    if buffer.len() < MIN_TCP_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_TCP_SIZE,
            actual: buffer.len(),
        });
    }

    let ip_header_len = (ip_header.ihl * 4) as usize;
    let tcp_offset = 14 + ip_header_len;

    // 获取TCP头部长度
    let tcp_header_len = ((buffer[tcp_offset + 12] >> 4) & 0xF) * 4;
    if tcp_header_len < 20 {
        return Err(TcpHeaderError::InvalidHeaderLength { length: tcp_header_len }.into());
    }

    let payload_offset = tcp_offset + tcp_header_len as usize;
    if payload_offset > buffer.len() {
        return Err(DecodeError::InsufficientLength {
            required: payload_offset,
            actual: buffer.len(),
        });
    }

    // 验证端口号
    let src_port = u16::from_be_bytes([buffer[tcp_offset], buffer[tcp_offset + 1]]);
    let dst_port = u16::from_be_bytes([buffer[tcp_offset + 2], buffer[tcp_offset + 3]]);
    if src_port == 0 || dst_port == 0 {
        return Err(TcpHeaderError::InvalidPort { port: if src_port == 0 { src_port } else { dst_port } }.into());
    }

    // 验证TCP标志
    let flags = buffer[tcp_offset + 13];
    if flags & 0x3F == 0 {
        return Err(TcpHeaderError::InvalidFlags { flags }.into());
    }

    // 使用预分配的 Vec 存储 payload
    let mut payload = Vec::with_capacity(buffer.len() - payload_offset);
    payload.extend_from_slice(&buffer[payload_offset..]);

    Ok(DecodedPacket {
        timestamp: packet.timestamp,
        ip_header: ip_header.clone(),
        src_port,
        dst_port,
        protocol: TransportProtocol::Tcp {
            seq: u32::from_be_bytes([
                buffer[tcp_offset + 4],
                buffer[tcp_offset + 5],
                buffer[tcp_offset + 6],
                buffer[tcp_offset + 7],
            ]),
            ack: u32::from_be_bytes([
                buffer[tcp_offset + 8],
                buffer[tcp_offset + 9],
                buffer[tcp_offset + 10],
                buffer[tcp_offset + 11],
            ]),
            flags,
            window: u16::from_be_bytes([buffer[tcp_offset + 14], buffer[tcp_offset + 15]]),
        },
        payload,
    })
}

/// 解码UDP包
fn decode_udp_packet(packet: &SafePacket, ip_header: &IpHeader) -> DecodeResult<DecodedPacket> {
    const MIN_UDP_SIZE: usize = 42; // 以太网(14) + IP(20) + UDP(8)
    if packet.data.len() < MIN_UDP_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_UDP_SIZE,
            actual: packet.data.len(),
        });
    }

    let ip_header_len = (ip_header.ihl * 4) as usize;
    let udp_offset = 14 + ip_header_len;
    let payload_offset = udp_offset + 8;  // UDP头部固定8字节

    // 验证UDP长度
    let udp_length = u16::from_be_bytes([packet.data[udp_offset + 4], packet.data[udp_offset + 5]]);
    if udp_length < 8 || udp_length > packet.data.len() as u16 - udp_offset as u16 {
        return Err(UdpHeaderError::InvalidLength { length: udp_length }.into());
    }

    // 验证端口号
    let src_port = u16::from_be_bytes([packet.data[udp_offset], packet.data[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([packet.data[udp_offset + 2], packet.data[udp_offset + 3]]);
    if src_port == 0 || dst_port == 0 {
        return Err(UdpHeaderError::InvalidPort { port: if src_port == 0 { src_port } else { dst_port } }.into());
    }

    // 提取payload
    let payload = packet.data[payload_offset..].to_vec();

    Ok(DecodedPacket {
        timestamp: packet.timestamp,
        ip_header: ip_header.clone(),
        src_port,
        dst_port,
        protocol: TransportProtocol::Udp,
        payload,
    })
}

/// 使用缓冲区解码UDP包
fn decode_udp_packet_with_buffer(
    packet: &SafePacket,
    buffer: &[u8],
    ip_header: &IpHeader,
) -> DecodeResult<DecodedPacket> {
    const MIN_UDP_SIZE: usize = 42; // 以太网(14) + IP(20) + UDP(8)
    if buffer.len() < MIN_UDP_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_UDP_SIZE,
            actual: buffer.len(),
        });
    }

    let ip_header_len = (ip_header.ihl * 4) as usize;
    let udp_offset = 14 + ip_header_len;
    let payload_offset = udp_offset + 8;  // UDP头部固定8字节

    // 验证UDP长度
    let udp_length = u16::from_be_bytes([buffer[udp_offset + 4], buffer[udp_offset + 5]]);
    if udp_length < 8 || udp_length > buffer.len() as u16 - udp_offset as u16 {
        return Err(UdpHeaderError::InvalidLength { length: udp_length }.into());
    }

    // 验证端口号
    let src_port = u16::from_be_bytes([buffer[udp_offset], buffer[udp_offset + 1]]);
    let dst_port = u16::from_be_bytes([buffer[udp_offset + 2], buffer[udp_offset + 3]]);
    if src_port == 0 || dst_port == 0 {
        return Err(UdpHeaderError::InvalidPort { port: if src_port == 0 { src_port } else { dst_port } }.into());
    }

    // 使用预分配的 Vec 存储 payload
    let mut payload = Vec::with_capacity(buffer.len() - payload_offset);
    payload.extend_from_slice(&buffer[payload_offset..]);

    Ok(DecodedPacket {
        timestamp: packet.timestamp,
        ip_header: ip_header.clone(),
        src_port,
        dst_port,
        protocol: TransportProtocol::Udp,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_packet() {
        // 创建测试数据包
        let test_packet = SafePacket::new(vec![
            // 以太网头部 (14字节)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 目标MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 源MAC
            0x08, 0x00,                         // 类型 (IPv4)
            // IP header
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // TCP header
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ], 0);

        // 测试解码
        let result = decode_packet(&test_packet);
        assert!(result.is_ok());
        
        let decoded = result.unwrap();
        assert_eq!(decoded.ip_header.protocol, 6); // TCP
        assert_eq!(decoded.src_port, 80);
        assert_eq!(decoded.dst_port, 80);
    }

    #[test]
    fn test_decode_packet_with_buffer() {
        // 创建测试数据包
        let test_packet = SafePacket::new(vec![
            // 以太网头部 (14字节)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 目标MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 源MAC
            0x08, 0x00,                         // 类型 (IPv4)
            // IP header
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // TCP header
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ], 0);

        // 创建预分配缓冲区
        let mut buffer = Vec::with_capacity(1024);
        
        // 测试解码
        let result = decode_packet_with_buffer(&test_packet, &mut buffer);
        assert!(result.is_ok());
        
        let decoded = result.unwrap();
        assert_eq!(decoded.ip_header.protocol, 6); // TCP
        assert_eq!(decoded.src_port, 80);
        assert_eq!(decoded.dst_port, 80);
    }

    #[test]
    fn test_decode_invalid_packet() {
        let invalid_packet = SafePacket::new(vec![], 0);
        let mut buffer = Vec::with_capacity(1024);
        
        let result = decode_packet(&invalid_packet);
        assert!(matches!(result, Err(DecodeError::EmptyPacket)));
        
        let result = decode_packet_with_buffer(&invalid_packet, &mut buffer);
        assert!(matches!(result, Err(DecodeError::EmptyPacket)));
    }

    #[test]
    fn test_decode_invalid_ip_version() {
        let mut packet = SafePacket::new(vec![0u8; 48], 0); // 14 + 34
        // 设置以太网类型为 IPv4
        packet.data[12] = 0x08;
        packet.data[13] = 0x00;
        // 设置 IPv6 版本
        packet.data[14] = 0x60;
        let mut buffer = Vec::with_capacity(1024);
        
        let result = decode_packet(&packet);
        println!("test_decode_invalid_ip_version result: {:?}", result);
        assert!(result.is_err());
        if let Err(DecodeError::Other(msg)) = result {
            assert!(msg.contains("IP头部错误"));
        }
        
        let result = decode_packet_with_buffer(&packet, &mut buffer);
        println!("test_decode_invalid_ip_version (buffer) result: {:?}", result);
        assert!(result.is_err());
        if let Err(DecodeError::Other(msg)) = result {
            assert!(msg.contains("IP头部错误"));
        }
    }

    #[test]
    fn test_decode_invalid_tcp_flags() {
        let mut packet = SafePacket::new(vec![0u8; 68], 0); // 14 + 54
        // 设置以太网类型为 IPv4
        packet.data[12] = 0x08;
        packet.data[13] = 0x00;
        // 设置有效的IP头部
        packet.data[14] = 0x45;
        packet.data[23] = 0x06; // TCP协议
        // 设置无效的TCP标志
        packet.data[47] = 0x00;
        let mut buffer = Vec::with_capacity(1024);
        
        let result = decode_packet(&packet);
        println!("test_decode_invalid_tcp_flags result: {:?}", result);
        assert!(result.is_err());
        if let Err(DecodeError::Other(msg)) = result {
            assert!(msg.contains("IP头部错误") || msg.contains("TCP"));
        }
        
        let result = decode_packet_with_buffer(&packet, &mut buffer);
        println!("test_decode_invalid_tcp_flags (buffer) result: {:?}", result);
        assert!(result.is_err());
        if let Err(DecodeError::Other(msg)) = result {
            assert!(msg.contains("IP头部错误") || msg.contains("TCP"));
        }
    }
}