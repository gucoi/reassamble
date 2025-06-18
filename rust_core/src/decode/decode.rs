use crate::SafePacket;
use super::error::{DecodeError, DecodeResult, IpHeaderError, TcpHeaderError, UdpHeaderError};
use bytes::BytesMut;
use super::decode_tcp::decode_tcp_packet;
use super::decode_udp::decode_udp_packet;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, Duration};
use super::DecodeContext;
use log::{trace, debug, info, warn, error};

// 以太网头部相关常量
const ETHERNET_HEADER_SIZE: usize = 14;
const ETHERNET_TYPE_IPV4: &[u8] = &[0x08, 0x00];
const ETHERNET_TYPE_IPV6: &[u8] = &[0x86, 0xDD];

// IP头部相关常量
const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV6_HEADER_SIZE: usize = 40;
const IPV4_VERSION_IHL: u8 = 0x45;  // 版本(4) + IHL(5)
const IPV4_PROTOCOL_TCP: u8 = 0x06;
const IPV4_PROTOCOL_UDP: u8 = 0x11;
const IPV4_PROTOCOL_ICMP: u8 = 0x01;

// TCP头部相关常量
const TCP_HEADER_SIZE: usize = 20;
const TCP_FLAGS_FIN: u8 = 0x01;
const TCP_FLAGS_SYN: u8 = 0x02;
const TCP_FLAGS_RST: u8 = 0x04;
const TCP_FLAGS_PSH: u8 = 0x08;
const TCP_FLAGS_ACK: u8 = 0x10;
const TCP_FLAGS_PSH_ACK: u8 = 0x18;

// UDP头部相关常量
const UDP_HEADER_SIZE: usize = 8;

// 最小包大小
const MIN_PACKET_SIZE: usize = ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE;

// 分片重组相关常量
const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_FRAGMENTS: usize = 16;

/// IP头部结构
#[derive(Debug, Clone)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_ip: u32,
    pub dest_ip: u32,
}

/// 解码后的数据包结构
#[derive(Debug, Clone)]
pub struct DecodedPacket {
    pub ip_header: IpHeader,
    pub protocol: TransportProtocol,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

impl DecodedPacket {
    pub fn to_vec(&self) -> Vec<u8> {
        match &self.protocol {
            TransportProtocol::TCP { payload, .. } => payload.to_vec(),
            _ => Vec::new(),
        }
    }
}

/// 分片结构
#[derive(Debug, Clone)]
struct Fragment {
    data: Vec<u8>,
    offset: u16,
    timestamp: Instant,
}

/// 分片组结构
#[derive(Debug)]
struct FragmentGroup {
    fragments: Vec<Fragment>,
    total_length: usize,
    last_update: Instant,
}

/// 全局分片重组器
lazy_static::lazy_static! {
    static ref FRAGMENT_REASSEMBLER: Mutex<HashMap<(u32, u32, u16), FragmentGroup>> = Mutex::new(HashMap::new());
}

/// 解码IP头部
pub fn decode_ip_header(data: &[u8]) -> DecodeResult<IpHeader> {
    trace!("开始解码IP头部，数据长度: {}", data.len());
    
    if data.len() < IPV4_MIN_HEADER_SIZE {
        warn!("IP头部数据太短: {} < {}", data.len(), IPV4_MIN_HEADER_SIZE);
        return Err(DecodeError::IpHeaderError(IpHeaderError::TooShort));
    }

    // 检查 IP 版本
    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        warn!("不支持的IP版本: {}", version);
        return Err(DecodeError::IpHeaderError(IpHeaderError::UnsupportedVersion { version }));
    }

    // 对于 IPv4
    let ihl = data[0] & 0xF;
    if ihl < 5 {  // IHL 最小值为 5（20字节）
        warn!("IP头部长度字段无效: IHL={}", ihl);
        return Err(DecodeError::IpHeaderError(IpHeaderError::TooShort));
    }
    let header_length = ihl * 4;

    let flags_and_offset = u16::from_be_bytes([data[6], data[7]]);
    let flags = ((flags_and_offset >> 13) & 0x7) as u8;  // 取高3位作为标志位
    let fragment_offset = flags_and_offset & 0x1FFF;  // 低13位作为偏移量
    // 在网络字节序中，MF标志位是第1位 (0x1)，对应flags中的0x1
    let more_fragments = (flags & 0x1) != 0;  

    let ip_header = IpHeader {
        version,
        ihl,
        tos: data[1],
        total_length: u16::from_be_bytes([data[2], data[3]]),
        identification: u16::from_be_bytes([data[4], data[5]]),
        flags,
        fragment_offset,
        more_fragments,
        ttl: data[8],
        protocol: data[9],
        header_checksum: u16::from_be_bytes([data[10], data[11]]),
        source_ip: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        dest_ip: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
    };
    
    debug!("IP头部解码成功: src_ip={}, dst_ip={}, protocol={}, flags=0x{:x}, fragment_offset={}, more_fragments={}", 
           ip_header.source_ip, ip_header.dest_ip, ip_header.protocol, ip_header.flags, 
           ip_header.fragment_offset, ip_header.more_fragments);
    
    Ok(ip_header)
}

/// 使用预分配缓冲区解码数据包（支持上下文统计与错误）
pub fn decode_packet(ctx: &mut DecodeContext, packet: &SafePacket, buffer: &[u8]) -> DecodeResult<DecodedPacket> {
    let start_time = Instant::now();
    trace!("开始解码数据包，缓冲区大小: {}", buffer.len());
    
    if buffer.len() < ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE {
        warn!("数据包太短，无法包含以太网和IP头部: {} < {}", 
              buffer.len(), ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE);
        ctx.record_error("数据包太短，无法包含以太网和IP头部");
        return Err(DecodeError::IpHeaderError(IpHeaderError::TooShort));
    }
    ctx.stats.ethernet_packets += 1;

    // 跳过以太网头部
    let ip_data = &buffer[ETHERNET_HEADER_SIZE..];
    trace!("跳过以太网头部，IP数据长度: {}", ip_data.len());
    
    let ip_header = match decode_ip_header(ip_data) {
        Ok(h) => {
            ctx.stats.ipv4_packets += 1;
            debug!("IP头部解码成功，协议: {}", h.protocol);
            h
        },
        Err(e) => {
            error!("IP头部解码失败: {:?}", e);
            ctx.record_error(&format!("IP头部解码失败: {:?}", e));
            return Err(e);
        }
    };
    let ip_header_size = ip_header.ihl as usize * 4;
    
    if ip_data.len() < ip_header_size {
        warn!("IP头部长度字段超出实际数据长度: {} < {}", ip_data.len(), ip_header_size);
        ctx.record_error("IP头部长度字段超出实际数据长度");
        return Err(DecodeError::IpHeaderError(IpHeaderError::TooShort));
    }
    
    let payload = &ip_data[ip_header_size..];
    trace!("IP头部解析完成，负载长度: {}", payload.len());
    
    let protocol = if ip_header.fragment_offset == 0 {
        // 只有第一个分片包含TCP/UDP头部
        debug!("处理非分片数据包，协议: {}", ip_header.protocol);
        match ip_header.protocol {
            0x06 => {
                if payload.len() < TCP_HEADER_SIZE {
                    warn!("TCP头部太短: {} < {}", payload.len(), TCP_HEADER_SIZE);
                    ctx.record_error("TCP头部太短");
                    return Err(DecodeError::TcpHeaderError(TcpHeaderError::TooShort));
                }
                ctx.stats.tcp_packets += 1;
                trace!("开始解码TCP包");
                match decode_tcp_packet(ctx, payload) {
                    Ok(tcp_protocol) => {
                        debug!("TCP包解码成功");
                        tcp_protocol
                    },
                    Err(e) => {
                        error!("TCP包解码失败: {:?}", e);
                        return Err(e);
                    }
                }
            },
            0x11 => {
                if payload.len() < UDP_HEADER_SIZE {
                    warn!("UDP头部太短: {} < {}", payload.len(), UDP_HEADER_SIZE);
                    ctx.record_error("UDP头部太短");
                    return Err(DecodeError::UdpHeaderError(UdpHeaderError::TooShort));
                }
                ctx.stats.udp_packets += 1;
                trace!("开始解码UDP包");
                match decode_udp_packet(ctx, payload) {
                    Ok(udp_protocol) => {
                        debug!("UDP包解码成功");
                        udp_protocol
                    },
                    Err(e) => {
                        error!("UDP包解码失败: {:?}", e);
                        return Err(e);
                    }
                }
            },
            _ => {
                warn!("不支持的IP协议: {}", ip_header.protocol);
                ctx.record_error(&format!("不支持的IP协议: {}", ip_header.protocol));
                return Err(DecodeError::IpHeaderError(IpHeaderError::UnsupportedProtocol { protocol: ip_header.protocol }));
            }
        }
    } else {
        // 后续分片只包含数据部分
        debug!("处理分片数据包，偏移量: {}, 协议: {}", ip_header.fragment_offset, ip_header.protocol);
        match ip_header.protocol {
            0x06 => {
                ctx.stats.tcp_packets += 1;
                TransportProtocol::TCP {
                    src_port: 0,
                    dst_port: 0,
                    seq: 0,
                    ack: 0,
                    flags: 0,
                    window: 0,
                    payload: BytesMut::from(payload),
                }
            },
            0x11 => {
                ctx.stats.udp_packets += 1;
                TransportProtocol::UDP {
                    src_port: 0,
                    dst_port: 0,
                    payload: BytesMut::from(payload),
                }
            },
            _ => {
                warn!("分片数据包使用不支持的协议: {}", ip_header.protocol);
                ctx.record_error(&format!("分片数据包使用不支持的协议: {}", ip_header.protocol));
                return Err(DecodeError::IpHeaderError(IpHeaderError::UnsupportedProtocol { protocol: ip_header.protocol }));
            }
        }
    };

    let decoded_packet = DecodedPacket {
        ip_header,
        protocol,
        timestamp: packet.timestamp,
        payload: payload.to_vec(),
    };
    
    let processing_time = start_time.elapsed();
    info!("数据包解码完成: 处理时间={:?}, 协议={:?}, 负载长度={}", 
          processing_time, 
          match &decoded_packet.protocol {
              TransportProtocol::TCP { .. } => "TCP",
              TransportProtocol::UDP { .. } => "UDP",
          },
          payload.len());
    
    Ok(decoded_packet)
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    TCP {
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        src_port: u16,
        dst_port: u16,
        payload: BytesMut,
    },
    UDP {
        src_port: u16,
        dst_port: u16,
        payload: BytesMut,
    },
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
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,     // 目标MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,     // 源MAC
            0x08, 0x00,                             // 类型 (IPv4)
            // IP header (20字节)
            0x45, 0x00, 0x00, 0x3c,             // 版本(4) + IHL(5), 总长度(60)
            0x00, 0x01, 0x40, 0x00,             // 标识, 标志, 片偏移
            0x40, 0x06, 0x00, 0x00,             // TTL(64), 协议(TCP), 校验和
            0x7f, 0x00, 0x00, 0x01,             // 源IP(127.0.0.1)
            0x7f, 0x00, 0x00, 0x01,             // 目标IP(127.0.0.1)
            // TCP header (20字节)
            0x00, 0x50, 0x00, 0x50,             // 源端口(80), 目标端口(80)
            0x00, 0x00, 0x00, 0x00,             // 序列号
            0x00, 0x00, 0x00, 0x00,             // 确认号
            0x50, 0x02, 0x20, 0x00,             // 数据偏移(5), 标志(SYN), 窗口大小
            0x00, 0x00, 0x00, 0x00,             // 校验和, 紧急指针
            // 填充数据
            0x00
        ][..]), 0);

        // 测试解码
        let result = decode_packet(&mut DecodeContext::new(), &test_packet, &test_packet.data[..]);
        assert!(result.is_ok());
        
        let decoded = result.unwrap();
        assert_eq!(decoded.ip_header.version, 4);
        assert_eq!(decoded.ip_header.protocol, 6);
        
        match decoded.protocol {
            TransportProtocol::TCP { seq, flags, window, src_port, dst_port, .. } => {
                assert_eq!(seq, 0);
                assert_eq!(flags, 0x02);  // SYN 标志
                assert_eq!(window, 0x2000);
                assert_eq!(src_port, 80);
                assert_eq!(dst_port, 80);
            },
            _ => panic!("Expected TCP protocol"),
        }
    }

    #[test]
    fn test_decode_invalid_ip_version() {
        let packet = SafePacket::new(BytesMut::from(&[
            // 以太网头部 (14字节)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,     // 目标MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,     // 源MAC
            0x08, 0x00,                             // 类型 (IPv4)
            // IP header (20字节)
            0x60, 0x00, 0x00, 0x3c,             // 版本(6) + IHL(0), 总长度(60)
            0x00, 0x01, 0x40, 0x00,             // 标识, 标志, 片偏移
            0x40, 0x06, 0x00, 0x00,             // TTL(64), 协议(TCP), 校验和
            0x7f, 0x00, 0x00, 0x01,             // 源IP(127.0.0.1)
            0x7f, 0x00, 0x00, 0x01,             // 目标IP(127.0.0.1)
        ][..]), 0);
        
        let result = decode_packet(&mut DecodeContext::new(), &packet, &packet.data[..]);
        assert!(result.is_err());
        match result {
            Err(DecodeError::IpHeaderError(IpHeaderError::UnsupportedVersion { version })) => {
                assert_eq!(version, 6);
            }
            _ => panic!("Expected UnsupportedVersion error"),
        }
    }

    #[test]
    fn test_decode_invalid_tcp_flags() {
        let packet = SafePacket::new(BytesMut::from(&[
            // 以太网头部 (14字节)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,     // 目标MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,     // 源MAC
            0x08, 0x00,                             // 类型 (IPv4)
            // IP header (20字节)
            0x45, 0x00, 0x00, 0x3c,             // 版本(4) + IHL(5), 总长度(60)
            0x00, 0x01, 0x40, 0x00,             // 标识, 标志, 片偏移
            0x40, 0x06, 0x00, 0x00,             // TTL(64), 协议(TCP), 校验和
            0x7f, 0x00, 0x00, 0x01,             // 源IP(127.0.0.1)
            0x7f, 0x00, 0x00, 0x01,             // 目标IP(127.0.0.1)
            // TCP header (20字节)
            0x00, 0x50, 0x00, 0x50,             // 源端口(80), 目标端口(80)
            0x00, 0x00, 0x00, 0x00,             // 序列号
            0x00, 0x00, 0x00, 0x00,             // 确认号
            0x50, 0x00, 0x20, 0x00,             // 数据偏移(5), 标志(无), 窗口大小
            0x00, 0x00, 0x00, 0x00              // 校验和, 紧急指针
        ][..]), 0);

        let result = decode_packet(&mut DecodeContext::new(), &packet, &packet.data[..]);
        assert!(result.is_err());
        match result {
            Err(DecodeError::TcpHeaderError(TcpHeaderError::InvalidFlags(flags))) => {
                assert_eq!(flags, 0x00);
            }
            _ => panic!("Expected InvalidFlags error"),
        }
    }

    #[test]
    fn test_decode_ipv6() {
        // 由于我们不支持 IPv6，这个测试应该返回 UnsupportedVersion 错误
        let packet = SafePacket::new(BytesMut::from(&[
            // 以太网头部 (14字节)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,     // 目标MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,     // 源MAC
            0x86, 0xDD,                             // 类型 (IPv6)
            // IP header (40字节)
            0x60, 0x00, 0x00, 0x00,             // 版本(6) + 流量类别 + 流标签
            0x00, 0x14, 0x06, 0x40,             // 负载长度(20字节TCP) + 下一个头部(TCP) + 跳数限制
            // 源地址 (::1)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // 目标地址 (::1)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ][..]), 0);
        
        let result = decode_packet(&mut DecodeContext::new(), &packet, &packet.data[..]);
        assert!(result.is_err());
        match result {
            Err(DecodeError::IpHeaderError(IpHeaderError::UnsupportedVersion { version })) => {
                assert_eq!(version, 6);
            }
            _ => panic!("Expected UnsupportedVersion error"),
        }
    }
}