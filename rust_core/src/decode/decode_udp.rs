use crate::decode::decode::{DecodedPacket, decode_ip_header};
use crate::Packet;

use super::decode::TransportProtocol;

pub fn decode_udp_packet(packet: &Packet) -> Option<DecodedPacket> {
    unsafe {
        if packet.data.is_null() || packet.len == 0 {
            return None;
        }

        let data = std::slice::from_raw_parts(packet.data, packet.len);
        
        // 验证最小UDP包大小
        if data.len() < 42 {  // 以太网(14) + IP(20) + UDP(8)
            return None;
        }

        // 获取IP头部长度
        let ip_header_len = (data[14] & 0x0f) * 4;
        let udp_offset = 14 + ip_header_len as usize;
        let payload_offset = udp_offset + 8;  // UDP头部固定8字节

        Some(DecodedPacket {
            timestamp: packet.timestamp,
            ip_header: decode_ip_header(&data[14..udp_offset])?,
            src_port: ((data[udp_offset] as u16) << 8) | data[udp_offset + 1] as u16,
            dst_port: ((data[udp_offset + 2] as u16) << 8) | data[udp_offset + 3] as u16,
            payload: data[payload_offset..].to_vec(),
            protocol: TransportProtocol::Udp,
        })
    }
}