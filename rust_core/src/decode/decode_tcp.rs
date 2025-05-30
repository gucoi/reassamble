use crate::SafePacket;
use super::error::{DecodeError, DecodeResult, TcpHeaderError};
use super::decode::{IpHeader, DecodedPacket, TransportProtocol};

// TCP相关常量
const MIN_TCP_SIZE: usize = 54;  // 以太网(14) + IP(20) + TCP(20)
const TCP_HEADER_LENGTH_MASK: u8 = 0xF0;  // 用于获取TCP头部长度的掩码
const TCP_HEADER_LENGTH_SHIFT: u8 = 4;    // TCP头部长度位移
const TCP_HEADER_MIN_SIZE: u8 = 20;       // TCP头部最小大小
const TCP_FLAGS_MASK: u8 = 0x3F;          // TCP标志掩码
const TCP_PORT_OFFSET: usize = 0;         // TCP源端口偏移
const TCP_DEST_PORT_OFFSET: usize = 2;    // TCP目标端口偏移
const TCP_SEQ_OFFSET: usize = 4;          // TCP序列号偏移
const TCP_ACK_OFFSET: usize = 8;          // TCP确认号偏移
const TCP_FLAGS_OFFSET: usize = 13;       // TCP标志偏移
const TCP_WINDOW_OFFSET: usize = 14;      // TCP窗口大小偏移

/// 解码TCP包
pub fn decode_tcp_packet(packet: &SafePacket, ip_header: &IpHeader) -> DecodeResult<DecodedPacket> {
    if packet.data.len() < MIN_TCP_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_TCP_SIZE,
            actual: packet.data.len(),
        });
    }

    let ip_header_len = (packet.data[14] & 0x0f) * 4;
    let tcp_offset = 14 + ip_header_len as usize;

    // 获取TCP头部长度
    let tcp_header_len = ((packet.data[tcp_offset + 12] & TCP_HEADER_LENGTH_MASK) >> TCP_HEADER_LENGTH_SHIFT) * 4;
    if tcp_header_len < TCP_HEADER_MIN_SIZE {
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
    let src_port = u16::from_be_bytes([packet.data[tcp_offset + TCP_PORT_OFFSET], packet.data[tcp_offset + TCP_PORT_OFFSET + 1]]);
    let dst_port = u16::from_be_bytes([packet.data[tcp_offset + TCP_DEST_PORT_OFFSET], packet.data[tcp_offset + TCP_DEST_PORT_OFFSET + 1]]);
    if src_port == 0 || dst_port == 0 {
        return Err(TcpHeaderError::InvalidPort { port: if src_port == 0 { src_port } else { dst_port } }.into());
    }

    // 验证TCP标志
    let flags = packet.data[tcp_offset + TCP_FLAGS_OFFSET];
    if flags & TCP_FLAGS_MASK == 0 {
        return Err(TcpHeaderError::InvalidFlags { flags }.into());
    }

    // 提取payload
    let payload = packet.data[payload_offset..].to_vec();

    Ok(DecodedPacket {
        timestamp: packet.timestamp,
        ip_header: ip_header.clone(),
        src_port,
        dst_port,
        protocol: TransportProtocol::TCP {
            seq: u32::from_be_bytes([
                packet.data[tcp_offset + TCP_SEQ_OFFSET],
                packet.data[tcp_offset + TCP_SEQ_OFFSET + 1],
                packet.data[tcp_offset + TCP_SEQ_OFFSET + 2],
                packet.data[tcp_offset + TCP_SEQ_OFFSET + 3],
            ]),
            ack: u32::from_be_bytes([
                packet.data[tcp_offset + TCP_ACK_OFFSET],
                packet.data[tcp_offset + TCP_ACK_OFFSET + 1],
                packet.data[tcp_offset + TCP_ACK_OFFSET + 2],
                packet.data[tcp_offset + TCP_ACK_OFFSET + 3],
            ]),
            flags,
            window: u16::from_be_bytes([
                packet.data[tcp_offset + TCP_WINDOW_OFFSET],
                packet.data[tcp_offset + TCP_WINDOW_OFFSET + 1],
            ]),
        },
        payload: payload.into(),
    })
}

/// 使用缓冲区解码TCP包
pub fn decode_tcp_packet_with_buffer(
    packet: &SafePacket,
    buffer: &[u8],
    ip_header: &IpHeader,
) -> DecodeResult<DecodedPacket> {
    if buffer.len() < MIN_TCP_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_TCP_SIZE,
            actual: buffer.len(),
        });
    }

    let ip_header_len = (buffer[14] & 0x0f) * 4;
    let tcp_offset = 14 + ip_header_len as usize;

    // 获取TCP头部长度
    let tcp_header_len = ((buffer[tcp_offset + 12] & TCP_HEADER_LENGTH_MASK) >> TCP_HEADER_LENGTH_SHIFT) * 4;
    if tcp_header_len < TCP_HEADER_MIN_SIZE {
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
    let src_port = u16::from_be_bytes([buffer[tcp_offset + TCP_PORT_OFFSET], buffer[tcp_offset + TCP_PORT_OFFSET + 1]]);
    let dst_port = u16::from_be_bytes([buffer[tcp_offset + TCP_DEST_PORT_OFFSET], buffer[tcp_offset + TCP_DEST_PORT_OFFSET + 1]]);
    if src_port == 0 || dst_port == 0 {
        return Err(TcpHeaderError::InvalidPort { port: if src_port == 0 { src_port } else { dst_port } }.into());
    }

    // 验证TCP标志
    let flags = buffer[tcp_offset + TCP_FLAGS_OFFSET];
    if flags & TCP_FLAGS_MASK == 0 {
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
        protocol: TransportProtocol::TCP {
            seq: u32::from_be_bytes([
                buffer[tcp_offset + TCP_SEQ_OFFSET],
                buffer[tcp_offset + TCP_SEQ_OFFSET + 1],
                buffer[tcp_offset + TCP_SEQ_OFFSET + 2],
                buffer[tcp_offset + TCP_SEQ_OFFSET + 3],
            ]),
            ack: u32::from_be_bytes([
                buffer[tcp_offset + TCP_ACK_OFFSET],
                buffer[tcp_offset + TCP_ACK_OFFSET + 1],
                buffer[tcp_offset + TCP_ACK_OFFSET + 2],
                buffer[tcp_offset + TCP_ACK_OFFSET + 3],
            ]),
            flags,
            window: u16::from_be_bytes([
                buffer[tcp_offset + TCP_WINDOW_OFFSET],
                buffer[tcp_offset + TCP_WINDOW_OFFSET + 1],
            ]),
        },
        payload: payload.into(),
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