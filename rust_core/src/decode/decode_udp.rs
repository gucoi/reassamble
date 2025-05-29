use crate::SafePacket;
use super::error::{DecodeError, DecodeResult, UdpHeaderError};
use super::decode::{IpHeader, DecodedPacket, TransportProtocol};

/// 解码UDP包
pub fn decode_udp_packet(packet: &SafePacket, ip_header: &IpHeader) -> DecodeResult<DecodedPacket> {
    const MIN_UDP_SIZE: usize = 42; // 以太网(14) + IP(20) + UDP(8)
    if packet.data.len() < MIN_UDP_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_UDP_SIZE,
            actual: packet.data.len(),
        });
    }

    let ip_header_len = (packet.data[14] & 0x0f) * 4;
    let udp_offset = 14 + ip_header_len as usize;
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
pub fn decode_udp_packet_with_buffer(
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

    let ip_header_len = (buffer[14] & 0x0f) * 4;
    let udp_offset = 14 + ip_header_len as usize;
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
    fn test_decode_udp_packet() {
        let test_packet = SafePacket::new(vec![
            0x45, 0x00, 0x00, 0x1C, // IP header
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // UDP header
            0x00, 0x35, 0x00, 0x35,
            0x00, 0x08, 0x00, 0x00
        ], 0);

        let ip_header = super::super::decode::decode_ip_header(&test_packet.data[14..]).unwrap();
        let result = decode_udp_packet(&test_packet, &ip_header);
        assert!(result.is_ok());
        
        let decoded = result.unwrap();
        assert_eq!(decoded.src_port, 53);
        assert_eq!(decoded.dst_port, 53);
    }

    #[test]
    fn test_decode_invalid_udp_length() {
        let mut packet = SafePacket::new(vec![0u8; 42], 0);
        // 设置有效的IP头部
        packet.data[0] = 0x45;
        packet.data[9] = 0x11; // UDP协议
        // 设置无效的UDP长度
        packet.data[38] = 0x00;
        packet.data[39] = 0x04; // 长度小于8
        
        let ip_header = super::super::decode::decode_ip_header(&packet.data[14..]).unwrap();
        let result = decode_udp_packet(&packet, &ip_header);
        assert!(matches!(result, Err(DecodeError::UdpHeaderError(_))));
    }
} 