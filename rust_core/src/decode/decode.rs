use std::net::IpAddr;
use crate::SafePacket;
use super::error::{DecodeError, DecodeResult, IpHeaderError, TcpHeaderError, UdpHeaderError, BufferError};
use bytes::BytesMut;

// 以太网头部相关常量
const ETHERNET_HEADER_SIZE: usize = 14;
const ETHERNET_TYPE_IPV4: &[u8] = &[0x08, 0x00];
const ETHERNET_TYPE_IPV6: &[u8] = &[0x86, 0xdd];

// IP头部相关常量
const IPV4_VERSION_IHL: u8 = 0x45;  // 版本(4) + IHL(5)
const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_PROTOCOL_TCP: u8 = 0x06;
const IPV4_PROTOCOL_UDP: u8 = 0x11;
const IPV4_PROTOCOL_ICMP: u8 = 0x01;

// TCP头部相关常量
const TCP_HEADER_SIZE: usize = 20;
const TCP_FLAGS_PSH: u8 = 0x08;
const TCP_FLAGS_ACK: u8 = 0x10;
const TCP_FLAGS_PSH_ACK: u8 = 0x18;

// 最小包大小
const MIN_PACKET_SIZE: usize = ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE;

/// IP头部结构
#[derive(Debug, Clone)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u16,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_ip: u32,
    pub dest_ip: u32,
}

/// 传输层协议类型
#[derive(Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    TCP {
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
    },
    UDP {
        length: u16,
        checksum: u16,
    },
    ICMP {
        type_: u8,
        code: u8,
        checksum: u16,
    },
    IPv6 {
        next_header: u8,
        hop_limit: u8,
    },
    Other(u8),
}

/// 解码后的数据包结构
#[derive(Debug, Clone)]
pub struct DecodedPacket {
    pub protocol: TransportProtocol,
    pub timestamp: u64,
    pub ip_header: IpHeader,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: BytesMut,
}

impl DecodedPacket {
    pub fn to_vec(&self) -> Vec<u8> {
        self.payload.to_vec()
    }
}

/// 解码IP头部
pub fn decode_ip_header(data: &[u8]) -> DecodeResult<IpHeader> {
    if data.len() < IPV4_MIN_HEADER_SIZE {
        return Err(IpHeaderError::TooShort.into());
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0F) * 4;

    if version != 4 {
        return Err(IpHeaderError::UnsupportedVersion { version }.into());
    }

    if data.len() < ihl as usize {
        return Err(IpHeaderError::TooShort.into());
    }

    let total_length = u16::from_be_bytes([data[2], data[3]]);
    if total_length < ihl as u16 {
        return Err(IpHeaderError::InvalidTotalLength { length: total_length }.into());
    }

    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_fragment = u16::from_be_bytes([data[6], data[7]]);
    let flags = (flags_fragment >> 13) & 0x7;
    let fragment_offset = flags_fragment & 0x1FFF;
    let ttl = data[8];
    let protocol = data[9];
    let header_checksum = u16::from_be_bytes([data[10], data[11]]);
    let source_ip = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let dest_ip = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

    Ok(IpHeader {
        version,
        ihl,
        tos: data[1],
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        source_ip,
        dest_ip,
    })
}

/// 解码数据包
pub fn decode_packet(packet: &SafePacket) -> DecodeResult<DecodedPacket> {
    let data = &packet.data;
    if data.is_empty() {
        return Err(DecodeError::EmptyPacket);
    }

    if data.len() < MIN_PACKET_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_PACKET_SIZE,
            actual: data.len(),
        });
    }

    let protocol = match &data[12..14] {
        ETHERNET_TYPE_IPV4 => {
            if data.len() < MIN_PACKET_SIZE {
                return Err(DecodeError::InsufficientLength {
                    required: MIN_PACKET_SIZE,
                    actual: data.len(),
                });
            }
            match data[23] {
                IPV4_PROTOCOL_TCP => TransportProtocol::TCP {
                    seq: u32::from_be_bytes([
                        data[34], data[35], data[36], data[37]
                    ]),
                    ack: u32::from_be_bytes([
                        data[38], data[39], data[40], data[41]
                    ]),
                    flags: data[42],
                    window: u16::from_be_bytes([data[43], data[44]]),
                },
                IPV4_PROTOCOL_UDP => TransportProtocol::UDP {
                    length: u16::from_be_bytes([data[34], data[35]]),
                    checksum: u16::from_be_bytes([data[36], data[37]]),
                },
                IPV4_PROTOCOL_ICMP => TransportProtocol::ICMP {
                    type_: data[34],
                    code: data[35],
                    checksum: u16::from_be_bytes([data[36], data[37]]),
                },
                _ => TransportProtocol::Other(data[23]),
            }
        }
        ETHERNET_TYPE_IPV6 => TransportProtocol::IPv6 {
            next_header: data[14],
            hop_limit: data[15],
        },
        _ => TransportProtocol::Other(data[12]),
    };

    let ip_header = decode_ip_header(&data[ETHERNET_HEADER_SIZE..])?;
    let src_port = u16::from_be_bytes([data[34], data[35]]);
    let dst_port = u16::from_be_bytes([data[36], data[37]]);
    let payload = BytesMut::from(&data[38..]);

    Ok(DecodedPacket {
        protocol,
        timestamp: packet.timestamp,
        ip_header,
        src_port,
        dst_port,
        payload,
    })
}

/// 使用预分配缓冲区解码数据包
pub fn decode_packet_with_buffer(packet: &SafePacket, buffer: &mut Vec<u8>) -> DecodeResult<DecodedPacket> {
    // 检查数据包是否为空
    if packet.data.is_empty() {
        return Err(DecodeError::EmptyPacket);
    }

    // 检查缓冲区容量
    if buffer.capacity() < packet.data.len() {
        return Err(BufferError::Overflow.into());
    }
    
    // 清空缓冲区并复制数据
    buffer.clear();
    buffer.extend_from_slice(&packet.data);

    // 验证最小包大小
    if buffer.len() < MIN_PACKET_SIZE {
        return Err(DecodeError::InsufficientLength {
            required: MIN_PACKET_SIZE,
            actual: buffer.len(),
        });
    }

    // 解码IP头部
    let ip_header = decode_ip_header(&buffer[ETHERNET_HEADER_SIZE..])?;

    // 根据协议类型解码
    match buffer[23] {
        IPV4_PROTOCOL_TCP => {
            let tcp_offset = ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE;
            if buffer.len() < tcp_offset + TCP_HEADER_SIZE {
                return Err(TcpHeaderError::TooShort.into());
            }

            let flags = buffer[tcp_offset + 13];
            if flags & 0x3F == 0 {
                return Err(TcpHeaderError::InvalidFlags { flags }.into());
            }

            let src_port = u16::from_be_bytes([buffer[tcp_offset], buffer[tcp_offset + 1]]);
            let dst_port = u16::from_be_bytes([buffer[tcp_offset + 2], buffer[tcp_offset + 3]]);
            if src_port == 0 || dst_port == 0 {
                return Err(TcpHeaderError::InvalidPort { 
                    port: if src_port == 0 { src_port } else { dst_port } 
                }.into());
            }

            let payload_offset = tcp_offset + TCP_HEADER_SIZE;

            Ok(DecodedPacket {
                timestamp: packet.timestamp,
                protocol: TransportProtocol::TCP {
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
                ip_header,
                src_port,
                dst_port,
                payload: BytesMut::from(&buffer[payload_offset..]),
            })
        }
        _ => Err(DecodeError::UnsupportedProtocol { protocol: buffer[23] }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_decode_packet() {
        // 创建测试数据包
        let test_packet = SafePacket::new(BytesMut::from(&[
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
        ][..]), 0);

        // 测试解码
        let result = decode_packet(&test_packet);
        assert!(result.is_ok());
        
        let decoded = result.unwrap();
        assert_eq!(decoded.protocol, TransportProtocol::TCP {
            seq: u32::from_be_bytes([
                0x00, 0x50, 0x00, 0x50
            ]),
            ack: u32::from_be_bytes([
                0x00, 0x00, 0x00, 0x00
            ]),
            flags: 0x02,
            window: u16::from_be_bytes([0x20, 0x00]),
        });
    }

    #[test]
    fn test_decode_invalid_packet() {
        let invalid_packet = SafePacket::new(BytesMut::new(), 0);
        let mut buffer = Vec::with_capacity(1024);
        
        let result = decode_packet(&invalid_packet);
        assert!(matches!(result, Err(DecodeError::EmptyPacket)));
        
        let result = decode_packet_with_buffer(&invalid_packet, &mut buffer);
        assert!(matches!(result, Err(DecodeError::EmptyPacket)));
    }

    #[test]
    fn test_decode_invalid_ip_version() {
        let mut packet = SafePacket::new(BytesMut::from(&vec![0u8; 48][..]), 0); // 14 + 34
        // 设置以太网类型为 IPv4
        packet.data[12] = 0x08;
        packet.data[13] = 0x00;
        // 设置 IPv6 版本
        packet.data[14] = 0x60;
        let mut buffer = Vec::with_capacity(1024);
        
        let result = decode_packet(&packet);
        assert!(result.is_err());
        if let Err(DecodeError::IpHeaderError(IpHeaderError::UnsupportedVersion { version })) = result {
            assert_eq!(version, 6);
        }
        
        let result = decode_packet_with_buffer(&packet, &mut buffer);
        assert!(result.is_err());
        if let Err(DecodeError::IpHeaderError(IpHeaderError::UnsupportedVersion { version })) = result {
            assert_eq!(version, 6);
        }
    }

    #[test]
    fn test_decode_invalid_tcp_flags() {
        let mut packet = SafePacket::new(BytesMut::from(&vec![0u8; 68][..]), 0); // 14 + 54
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
        assert!(result.is_err());
        if let Err(DecodeError::TcpHeaderError(TcpHeaderError::InvalidFlags { flags })) = result {
            assert_eq!(flags, 0x00);
        }
        
        let result = decode_packet_with_buffer(&packet, &mut buffer);
        assert!(result.is_err());
        if let Err(DecodeError::TcpHeaderError(TcpHeaderError::InvalidFlags { flags })) = result {
            assert_eq!(flags, 0x00);
        }
    }

    #[test]
    fn test_decode_ipv6() {
        let mut data = BytesMut::from(&vec![0u8; 48][..]);
        data[12] = 0x86;
        data[13] = 0xdd;
        data[14] = 0x60;
        
        let packet = SafePacket::new(data, 0);
        let result = decode_packet(&packet);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.protocol, TransportProtocol::IPv6 {
            next_header: 0x00,
            hop_limit: 0x00,
        });
    }

    #[test]
    fn test_decode_tcp() {
        let mut data = BytesMut::from(&vec![0u8; 68][..]);
        data[12] = 0x08;
        data[13] = 0x00;
        data[14] = 0x45;
        data[23] = 0x06; // TCP协议
        data[47] = 0x02; // 设置有效的TCP标志
        
        let packet = SafePacket::new(data, 0);
        let result = decode_packet(&packet);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.protocol, TransportProtocol::TCP {
            seq: u32::from_be_bytes([
                0x00, 0x50, 0x00, 0x50
            ]),
            ack: u32::from_be_bytes([
                0x00, 0x00, 0x00, 0x00
            ]),
            flags: 0x02,
            window: u16::from_be_bytes([0x20, 0x00]),
        });
    }
}