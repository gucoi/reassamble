use super::error::{DecodeResult, TcpHeaderError, DecodeError};
use super::decode::TransportProtocol;
use super::DecodeContext;
use bytes::BytesMut;
use log::{trace, debug, info, warn, error};

// TCP相关常量
const MIN_TCP_SIZE: usize = 54;  // 以太网(14) + IP(20) + TCP(20)
const TCP_HEADER_LENGTH_MASK: u8 = 0xF0;  // 用于获取TCP头部长度的掩码
const TCP_HEADER_LENGTH_SHIFT: u8 = 4;    // TCP头部长度位移
pub const TCP_HEADER_MIN_SIZE: usize = 20;       // TCP头部最小大小
const TCP_FLAGS_MASK: u8 = 0x3F;          // TCP标志掩码 (URG|ACK|PSH|RST|SYN|FIN)
const TCP_PORT_OFFSET: usize = 0;         // TCP源端口偏移
const TCP_DEST_PORT_OFFSET: usize = 2;    // TCP目标端口偏移
const TCP_SEQ_OFFSET: usize = 4;          // TCP序列号偏移
const TCP_ACK_OFFSET: usize = 8;          // TCP确认号偏移
const TCP_FLAGS_OFFSET: usize = 13;       // TCP标志偏移
const TCP_WINDOW_OFFSET: usize = 14;      // TCP窗口大小偏移

/// 使用缓冲区解码TCP包（支持上下文统计与错误）
pub fn decode_tcp_packet(ctx: &mut DecodeContext, buffer: &[u8]) -> DecodeResult<TransportProtocol> {
    trace!("开始解码TCP包，缓冲区大小: {}", buffer.len());
    
    if buffer.len() < TCP_HEADER_MIN_SIZE {
        warn!("TCP头部太短，无法解析: {} < {}", buffer.len(), TCP_HEADER_MIN_SIZE);
        ctx.record_error("TCP头部太短，无法解析");
        return Err(TcpHeaderError::TooShort.into());
    }

    let data_offset = ((buffer[12] & TCP_HEADER_LENGTH_MASK) >> TCP_HEADER_LENGTH_SHIFT) as usize;
    let header_length = data_offset * 4;
    
    trace!("TCP头部长度解析: data_offset={}, header_length={}", data_offset, header_length);
    
    if header_length < TCP_HEADER_MIN_SIZE {
        warn!("TCP头部长度无效: {} < {}", header_length, TCP_HEADER_MIN_SIZE);
        ctx.record_error(&format!("TCP头部长度无效: {}", header_length));
        return Err(TcpHeaderError::InvalidLength(header_length).into());
    }

    if header_length > buffer.len() {
        warn!("TCP头部长度超出缓冲区: {} > {}", header_length, buffer.len());
        ctx.record_error(&format!("TCP头部长度超出缓冲区: {} > {}", header_length, buffer.len()));
        return Err(TcpHeaderError::TooShort.into());
    }

    let src_port = u16::from_be_bytes([buffer[0], buffer[1]]);
    let dst_port = u16::from_be_bytes([buffer[2], buffer[3]]);
    let seq = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
    let ack = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
    let flags = buffer[13] & TCP_FLAGS_MASK;

    trace!("TCP头部字段解析: src_port={}, dst_port={}, seq={}, ack={}, flags=0x{:02x}", 
           src_port, dst_port, seq, ack, flags);

    // 验证TCP标志位
    if flags == 0 {
        warn!("TCP标志位无效: 0x{:02x}", flags);
        ctx.record_error(&format!("TCP标志位无效: 0x{:02x}", flags));
        return Err(TcpHeaderError::InvalidFlags(flags).into());
    }

    let window = u16::from_be_bytes([buffer[14], buffer[15]]);
    let payload = if buffer.len() > header_length {
        let payload_data = &buffer[header_length..];
        trace!("TCP负载数据: 长度={}", payload_data.len());
        BytesMut::from(payload_data)
    } else {
        trace!("TCP包无负载数据");
        BytesMut::new()
    };

    let payload_len = payload.len();
    let tcp_protocol = TransportProtocol::TCP {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload,
    };
    
    debug!("TCP包解码成功: src_port={}, dst_port={}, seq={}, ack={}, flags=0x{:02x}, window={}, payload_len={}", 
           src_port, dst_port, seq, ack, flags, window, payload_len);
    
    Ok(tcp_protocol)
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use super::*;
    use crate::SafePacket;

    #[test]
    fn test_decode_tcp_packet() {
        let test_packet = SafePacket::new(BytesMut::from(&[
            // TCP header
            0x00, 0x50, 0x00, 0x50,             // 源端口(80), 目标端口(80)
            0x00, 0x00, 0x00, 0x01,             // 序列号(1)
            0x00, 0x00, 0x00, 0x00,             // 确认号(0)
            0x50, 0x18, 0x20, 0x00,             // 数据偏移(5), 标志位(PSH|ACK), 窗口大小(8192)
            0x00, 0x00, 0x00, 0x00,             // 校验和(0), 紧急指针(0)
            // 数据部分
            0x48, 0x65, 0x6c, 0x6c, 0x6f       // "Hello"
        ][..]), 0);

        let mut ctx = DecodeContext::new();
        let result = decode_tcp_packet(&mut ctx, &test_packet.data[..]);
        assert!(result.is_ok());
        
        let decoded = result.unwrap();
        match decoded {
            TransportProtocol::TCP { src_port, dst_port, seq, ack, flags, window, payload } => {
                assert_eq!(src_port, 80, "源端口不匹配");
                assert_eq!(dst_port, 80, "目标端口不匹配");
                assert_eq!(seq, 1, "序列号不匹配");
                assert_eq!(ack, 0, "确认号不匹配");
                assert_eq!(flags, 0x18, "标志位不匹配");
                assert_eq!(window, 8192, "窗口大小不匹配");
                assert_eq!(&payload[..], b"Hello", "数据部分不匹配");
            }
            _ => panic!("Expected TCP protocol"),
        }
    }

    #[test]
    fn test_decode_invalid_tcp_flags() {
        let mut packet = SafePacket::new(BytesMut::from(&[
            // TCP header
            0x00, 0x50, 0x00, 0x50,             // 源端口(80), 目标端口(80)
            0x00, 0x00, 0x00, 0x01,             // 序列号(1)
            0x00, 0x00, 0x00, 0x00,             // 确认号(0)
            0x50, 0x00, 0x20, 0x00,             // 数据偏移(5), 标志位(无), 窗口大小(8192)
            0x00, 0x00, 0x00, 0x00              // 校验和(0), 紧急指针(0)
        ][..]), 0);
        
        let mut ctx = DecodeContext::new();
        let result = decode_tcp_packet(&mut ctx, &packet.data[..]);
        assert!(matches!(result, Err(DecodeError::TcpHeaderError(TcpHeaderError::InvalidFlags(_)))));
        assert_eq!(ctx.stats.errors, 1);
    }

    #[test]
    fn test_decode_invalid_header_length() {
        let mut packet = SafePacket::new(BytesMut::from(&[
            // TCP header
            0x00, 0x50, 0x00, 0x50,             // 源端口(80), 目标端口(80)
            0x00, 0x00, 0x00, 0x01,             // 序列号(1)
            0x00, 0x00, 0x00, 0x00,             // 确认号(0)
            0x00, 0x18, 0x20, 0x00,             // 数据偏移(0), 标志位(PSH|ACK), 窗口大小(8192)
            0x00, 0x00, 0x00, 0x00              // 校验和(0), 紧急指针(0)
        ][..]), 0);
        
        let mut ctx = DecodeContext::new();
        let result = decode_tcp_packet(&mut ctx, &packet.data[..]);
        assert!(matches!(result, Err(DecodeError::TcpHeaderError(TcpHeaderError::InvalidLength(_)))));
        assert_eq!(ctx.stats.errors, 1);
    }
} 