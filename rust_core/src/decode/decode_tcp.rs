use crate::SafePacket;
use super::error::{DecodeError, DecodeResult, TcpHeaderError};
use super::decode::{IpHeader, DecodedPacket, TransportProtocol};

/// 解码TCP包
pub fn decode_tcp_packet(packet: &SafePacket, ip_header: &IpHeader) -> DecodeResult<DecodedPacket> {
    const MIN_TCP_SIZE: usize = 54; // 以太网(14) + IP(20) + TCP(20)
    if packet.data.len() < MIN_TCP_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_TCP_SIZE,
            actual: packet.data.len(),
        });
    }

    let ip_header_len = (packet.data[14] & 0x0f) * 4;
    let tcp_offset = 14 + ip_header_len as usize;

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

    // 提取payload
    let payload = packet.data[payload_offset..].to_vec();

    Ok(DecodedPacket {
        timestamp: packet.timestamp,
        ip_header: ip_header.clone(),
        src_port,
        dst_port,
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
        payload,
    })
}

/// 使用缓冲区解码TCP包
pub fn decode_tcp_packet_with_buffer(
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

    let ip_header_len = (buffer[14] & 0x0f) * 4;
    let tcp_offset = 14 + ip_header_len as usize;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_tcp_packet() {
        let test_packet = SafePacket::new(vec![
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
        ], 0);

        let ip_header = super::super::decode::decode_ip_header(&test_packet.data[14..]).unwrap();
        let result = decode_tcp_packet(&test_packet, &ip_header);
        assert!(result.is_ok());
        
        let decoded = result.unwrap();
        assert_eq!(decoded.src_port, 80);
        assert_eq!(decoded.dst_port, 80);
    }

    #[test]
    fn test_decode_invalid_tcp_flags() {
        let mut packet = SafePacket::new(vec![0u8; 54], 0);
        // 设置有效的IP头部
        packet.data[0] = 0x45;
        packet.data[9] = 0x06; // TCP协议
        // 设置无效的TCP标志
        packet.data[47] = 0x00;
        
        let ip_header = super::super::decode::decode_ip_header(&packet.data[14..]).unwrap();
        let result = decode_tcp_packet(&packet, &ip_header);
        assert!(matches!(result, Err(DecodeError::TcpHeaderError(_))));
    }
} 