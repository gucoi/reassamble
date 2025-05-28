use std::net::IpAddr;

use crate::{decode::{decode_tcp_packet, decode_udp_packet}, SafePacket};

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

#[derive(Debug, Clone)]
pub enum TransportProtocol {
    Tcp {
        seq: u32,
        ack: u32,
        flags: u8, // TCP标志位 
        window: u16, // 窗口大小
    },
    Udp,
    Other(u8), // 其他协议
}


#[derive(Debug, Clone)]
pub struct DecodedPacket {
    pub timestamp: u64,
    pub ip_header: IpHeader,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
    pub protocol: TransportProtocol,
}

pub fn decode_ip_header(data: &[u8]) -> Option<IpHeader> {
    if data.len() < 20 {  // 最小IP头部长度
        return None;
    }

    let version = (data[0] >> 4) & 0xF;
    let ihl = data[0] & 0xF;
    
    Some(IpHeader {
        version,
        ihl,
        total_length: ((data[2] as u16) << 8) | data[3] as u16,
        identification: ((data[4] as u16) << 8) | data[5] as u16,
        flags: (data[6] >> 5) & 0x7,
        fragment_offset: ((data[6] as u16 & 0x1F) << 8) | data[7] as u16,
        ttl: data[8],
        protocol: data[9],
        checksum: ((data[10] as u16) << 8) | data[11] as u16,
        src_ip: IpAddr::V4(std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15])),
        dst_ip: IpAddr::V4(std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19])),
    })
}

pub fn decode_packet(packet: &SafePacket) -> Option<DecodedPacket> {
    unsafe {
        if packet.data.is_null() || packet.len == 0 {
            return None;
        }

        let data = std::slice::from_raw_parts(packet.data, packet.len);

        if data.len() < 34 { // 最小IP头部长度
            return None;
        }

        let ip_header = decode_ip_header(&data[14..34])?;

        match ip_header.protocol {
            6 => decode_tcp_packet(packet), // TCP
            17 => decode_udp_packet(packet), // UDP
            _ => None, // 其他协议暂不处理
        }
    }

}