use super::decode::DecodedPacket;
use crate::config::ReassembleConfig;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Debug)]
pub struct ReassembledStream {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub data: Vec<u8>,
    pub start_time: u64,
    pub end_time: u64,
}

lazy_static::lazy_static! {
    static ref STREAM_MAP: Mutex<HashMap<StreamKey, StreamAssembler>> = Mutex::new(HashMap::new());
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct StreamKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

struct StreamAssembler {
    segments: Vec<Vec<u8>>,
    start_time: u64,
    last_time: u64,
    config: ReassembleConfig,
}

pub fn reassemble_packet(packet: DecodedPacket) -> Option<ReassembledStream> {
    let key = StreamKey {
        src_ip: packet.src_ip,
        dst_ip: packet.dst_ip,
        src_port: packet.src_port,
        dst_port: packet.dst_port,
        protocol: packet.protocol,
    };

    let mut map = STREAM_MAP.lock().unwrap();
    let assembler = map.entry(key.clone()).or_insert(StreamAssembler {
        segments: Vec::new(),
        start_time: packet.timestamp,
        last_time: packet.timestamp,
        config: ReassembleConfig::default(),
    });

    assembler.segments.push(packet.payload);
    assembler.last_time = packet.timestamp;

    // 判断是否需要重组完成
    if is_stream_complete(assembler) {
        let stream = ReassembledStream {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            src_port: key.src_port,
            dst_port: key.dst_port,
            protocol: key.protocol,
            data: assemble_segments(&assembler.segments),
            start_time: assembler.start_time,
            end_time: assembler.last_time,
        };
        map.remove(&key);
        Some(stream)
    } else {
        None
    }
}

fn is_stream_complete(assembler: &StreamAssembler) -> bool {
    assembler.segments.len() > assembler.config.max_segments || 
        assembler.last_time - assembler.start_time > assembler.config.timeout * 1_000_000_000
}

fn assemble_segments(segments: &[Vec<u8>]) -> Vec<u8> {
    segments.iter().flat_map(|s| s.iter().cloned()).collect()
}