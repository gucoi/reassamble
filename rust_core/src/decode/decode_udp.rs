use super::error::{DecodeResult, UdpHeaderError, DecodeError};
use super::decode::TransportProtocol;
use super::DecodeContext;
use bytes::BytesMut;
use log::{trace, debug, info, warn, error};
use crate::SafePacket;

// UDP相关常量
const MIN_UDP_SIZE: usize = 42;  // 以太网(14) + IP(20) + UDP(8)
const UDP_HEADER_SIZE: usize = 8;  // UDP头部固定8字节
const UDP_SRC_PORT_OFFSET: usize = 0;  // UDP源端口偏移
const UDP_DEST_PORT_OFFSET: usize = 2;  // UDP目标端口偏移
const UDP_LENGTH_OFFSET: usize = 4;  // UDP长度偏移
const UDP_CHECKSUM_OFFSET: usize = 6;  // UDP校验和偏移

/// 使用缓冲区解码UDP包（支持上下文统计与错误）
pub fn decode_udp_packet(ctx: &mut DecodeContext, buffer: &[u8]) -> DecodeResult<TransportProtocol> {
    trace!("开始解码UDP包，缓冲区大小: {}", buffer.len());
    
    if buffer.len() < UDP_HEADER_SIZE {
        warn!("UDP头部太短，无法解析: {} < {}", buffer.len(), UDP_HEADER_SIZE);
        ctx.record_error("UDP头部太短，无法解析");
        return Err(UdpHeaderError::TooShort.into());
    }

    let src_port = u16::from_be_bytes([buffer[0], buffer[1]]);
    let dst_port = u16::from_be_bytes([buffer[2], buffer[3]]);
    let udp_length = u16::from_be_bytes([buffer[4], buffer[5]]);

    trace!("UDP头部字段解析: src_port={}, dst_port={}, length={}", src_port, dst_port, udp_length);

    if udp_length < UDP_HEADER_SIZE as u16 || udp_length as usize > buffer.len() {
        warn!("UDP长度无效: {} (头部大小: {}, 缓冲区大小: {})", 
              udp_length, UDP_HEADER_SIZE, buffer.len());
        ctx.record_error(&format!("UDP长度无效: {} (头部大小: {}, 缓冲区大小: {})", 
                                 udp_length, UDP_HEADER_SIZE, buffer.len()));
        return Err(UdpHeaderError::InvalidLength.into());
    }

    // 提取数据部分
    let payload = if buffer.len() > UDP_HEADER_SIZE {
        let payload_data = &buffer[UDP_HEADER_SIZE..];
        trace!("UDP负载数据: 长度={}", payload_data.len());
        BytesMut::from(payload_data)
    } else {
        trace!("UDP包无负载数据");
        BytesMut::new()
    };

    let payload_len = payload.len();
    let udp_protocol = TransportProtocol::UDP {
        src_port,
        dst_port,
        payload,
    };
    
    debug!("UDP包解码成功: src_port={}, dst_port={}, payload_len={}", 
           src_port, dst_port, payload_len);
    
    Ok(udp_protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use crate::SafePacket;

    #[test]
    fn test_decode_udp_packet() {
        let test_packet = SafePacket::new(BytesMut::from(&[
            // UDP头部 (8字节)
            0x00, 0x35, 0x00, 0x35,             // 源端口(53), 目标端口(53)
            0x00, 0x08, 0x00, 0x00,             // 长度(8), 校验和
            // 数据部分
            0x48, 0x65, 0x6c, 0x6c, 0x6f       // "Hello"
        ][..]), 0);

        let mut ctx = DecodeContext::new();
        let result = decode_udp_packet(&mut ctx, &test_packet.data);
        assert!(result.is_ok(), "UDP包解码失败: {:?}", result);
        
        let decoded = result.unwrap();
        match decoded {
            TransportProtocol::UDP { src_port, dst_port, payload } => {
                assert_eq!(src_port, 53, "源端口不匹配");
                assert_eq!(dst_port, 53, "目标端口不匹配");
                assert_eq!(&payload[..], b"Hello", "数据部分不匹配");
            }
            _ => panic!("Expected UDP protocol"),
        }
    }

    #[test]
    fn test_decode_invalid_udp_length() {
        let packet = SafePacket::new(BytesMut::from(&[
            // UDP头部 (8字节)
            0x00, 0x35, 0x00, 0x35,             // 源端口(53), 目标端口(53)
            0x00, 0x04, 0x00, 0x00              // 长度(4), 校验和 - 无效长度
        ][..]), 0);

        let mut ctx = DecodeContext::new();
        let result = decode_udp_packet(&mut ctx, &packet.data);
        assert!(matches!(result, Err(DecodeError::UdpHeaderError(_))), "应该返回UDP头部错误");
        assert_eq!(ctx.stats.errors, 1);
    }
} 