use super::decode::{DecodedPacket, decode_ip_header, TransportProtocol};
use crate::Packet;

pub fn decode_tcp_packet(packet: &Packet) -> Option<DecodedPacket> {
    unsafe {
        if packet.data.is_null() || packet.len == 0 {
            return None;
        }

        let data = std::slice::from_raw_parts(packet.data, packet.len);
        
        // 验证最小TCP包大小
        if data.len() < 54 {  // 以太网(14) + IP(20) + TCP(20)
            return None;
        }

        // 获取IP头部长度
        let ip_header_len = (data[14] & 0x0f) * 4;
        let tcp_offset = 14 + ip_header_len as usize;

        // TCP标志
        let tcp_flags = data[tcp_offset + 13];

        // 获取TCP头部长度
        let tcp_header_len = ((data[tcp_offset + 12] >> 4) & 0xF) * 4;
        let payload_offset = tcp_offset + tcp_header_len as usize;

        Some(DecodedPacket {
            timestamp: packet.timestamp,
            ip_header: decode_ip_header(&data[14..tcp_offset])?,
            src_port: ((data[tcp_offset] as u16) << 8) | data[tcp_offset + 1] as u16,
            dst_port: ((data[tcp_offset + 2] as u16) << 8) | data[tcp_offset + 3] as u16,
            protocol: TransportProtocol::Tcp {
                seq: ((data[tcp_offset + 4] as u32) << 24) |
                    ((data[tcp_offset + 5] as u32) << 16) |
                    ((data[tcp_offset + 6] as u32) << 8) |
                    data[tcp_offset + 7] as u32,
                ack: ((data[tcp_offset + 8] as u32) << 24) |
                    ((data[tcp_offset + 9] as u32) << 16) |
                    ((data[tcp_offset + 10] as u32) << 8) |
                    data[tcp_offset + 11] as u32,
                flags: tcp_flags,
                window: ((data[tcp_offset + 14] as u16) << 8) | data[tcp_offset + 15] as u16,
            },
            payload: data[payload_offset..].to_vec(),
        })
    }
}