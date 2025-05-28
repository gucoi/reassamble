use std::collections::{BTreeMap};
use tokio::time::{Duration, Instant};
use super::super::decode::DecodedPacket;
use parking_lot::RwLock;  // 使用 parking_lot 提供的更高效的读写锁
use dashmap::DashMap;     // 使用 DashMap 替代 HashMap
use std::sync::Arc;
use dashmap::mapref::entry::Entry;
use super::super::stream::StreamStats;
use crate::decode::TransportProtocol;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Debug)]
struct SackBlock {
    start_seq: u32,
    end_seq: u32,
}

#[derive(Debug)]
pub enum ReassemblyError {
    InvalidSequence(u32),
    GapTooLarge(u32),
    SegmentOverlap { existing: u32, new: u32 },
    InvalidState(TcpState),
}

#[derive(Debug)]
pub enum StreamEvent {
    Retransmission,
    GapDetected,
    NewSegment,
    StreamEstablished,
    StreamClosed,
    SegmentReassembled,
    OutOfOrder,
    Error(ReassemblyError),
}

#[derive(Debug)]
struct TcpStream {
    seq: u32,
    segments: BTreeMap<u32, TcpSegment>,  // 使用 BTreeMap 来维护有序的段
    last_ack: u32,
    last_seen: Instant,
    state: TcpState,
    isn: u32,  // 初始序列号
    fin_seq: Option<u32>,  // FIN 包的序列号
    sack_blocks: Vec<SackBlock>,
    stats: StreamStats,
    window_size: u32, // 窗口大小
    mss: u16, // 最后一个确认的最大段大小
}

#[derive(Debug)]
struct TcpSegment {
    seq: u32,
    data: Vec<u8>,
    received: Instant,
    retransmit_count: u32,
    last_retransmit: Option<Instant>,
}

pub struct TcpReassembler {
    streams: DashMap<String, Arc<RwLock<TcpStream>>>,
    timeout: Duration,
    max_gap: u32,
    max_streams: usize,
    max_segments: usize,
}

impl TcpReassembler {
    pub fn new(timeout_secs: u64, max_gap: u32, max_streams: usize, max_segments: usize) -> Self {
        TcpReassembler {
            streams: DashMap::with_capacity(max_streams),
            timeout: Duration::from_secs(timeout_secs),
            max_gap,
            max_streams,
            max_segments,
        }
    }

    pub fn process_packet(&self, packet: &DecodedPacket) -> Option<Vec<u8>> {
        let (seq, ack, flags, window) = match &packet.protocol {
            TransportProtocol::Tcp { seq, ack, flags, window } => {
                (*seq, *ack, *flags, *window)
            }
            _ => return None,
        };

        let now = Instant::now();
        self.cleanup_expired(now);
        
        let stream_key = format!("{}:{}-{}:{}",
            packet.ip_header.src_ip, packet.src_port,
            packet.ip_header.dst_ip, packet.dst_port);

        match self.streams.entry(stream_key) {
            Entry::Occupied(entry) => {
                let stream = entry.get();
                let mut stream_guard = stream.write();
                stream_guard.last_seen = now;
                
                if !packet.payload.is_empty() {
                    self.add_segment(&mut stream_guard, packet, now);
                }
                
                self.handle_tcp_flags(&mut stream_guard, packet);
                self.handle_retransmission(&mut stream_guard, packet);
                self.try_reassemble(&mut stream_guard)
            }
            Entry::Vacant(entry) => {
                if self.streams.len() >= self.max_streams {
                    self.find_and_remove_oldest_stream();
                }
                
                let new_stream = Arc::new(RwLock::new(TcpStream {
                    seq: seq,
                    segments: BTreeMap::new(),
                    last_ack: ack,
                    last_seen: now,
                    state: TcpState::Closed,
                    isn: seq,
                    fin_seq: None,
                    sack_blocks: Vec::new(),
                    window_size: 0,
                    mss: 1460,
                    stats: StreamStats::default(),
                }));

                if !packet.payload.is_empty() {
                    let mut stream = new_stream.write();
                    self.add_segment(&mut stream, packet, now);
                }
                
                entry.insert(new_stream);
                None
            }
        }
    }

    fn try_reassemble(&self, stream: &mut TcpStream) -> Option<Vec<u8>> {
        // 检查内存限制
        if !self.check_memory_limits(stream) {
            self.handle_error(
                ReassemblyError::InvalidState(stream.state),
                stream
            );
            return None;
        }

        if stream.segments.is_empty() {
            return None;
        }

        let mut reassembled = Vec::new();
        let mut next_seq = stream.seq;
        let mut gaps = Vec::new();
        let mut segments_to_remove = Vec::new();

        // 遍历有序段
        for (&seq, segment) in stream.segments.iter() {
            if seq == next_seq {
                // 连续的段
                reassembled.extend(&segment.data);
                next_seq += segment.data.len() as u32;
                segments_to_remove.push(seq);
            } else if seq > next_seq {
                // 发现 gap
                let gap_size = seq - next_seq;
                if gap_size <= self.max_gap {
                    // gap 在允许范围内，记录 gap 位置
                    gaps.push((next_seq, gap_size));
                    stream.stats.gaps_detected += 1;
                    self.update_stats(StreamEvent::GapDetected, stream);
                    break;
                } else {
                    // gap 太大，停止重组
                    self.handle_error(
                        ReassemblyError::GapTooLarge(gap_size),
                        stream
                    );
                    break;
                }
            } else if seq < next_seq {
                // 重叠段或重传段
                let overlap_size = next_seq - seq;
                if overlap_size < segment.data.len() as u32 {
                    // 部分重叠，取未重叠部分
                    let new_data = &segment.data[overlap_size as usize..];
                    reassembled.extend(new_data);
                    next_seq += new_data.len() as u32;
                }
                segments_to_remove.push(seq);
            }
        }

        // 如果成功重组了一些数据
        if !reassembled.is_empty() {
            // 更新流的状态
            stream.seq = next_seq;
            
            // 清理已重组的段
            for seq in segments_to_remove {
                stream.segments.remove(&seq);
            }

            // 更新统计信息
            stream.stats.byte_count += reassembled.len() as u64;
            self.update_stats(StreamEvent::SegmentReassembled, stream);

            Some(reassembled)
        } else {
            None
        }
    }

    fn add_segment(&self, stream: &mut TcpStream, packet: &DecodedPacket, now: Instant) {
        if stream.segments.len() >= self.max_segments {
            if let Some((&oldest_seq, _)) = stream.segments.iter()
                .min_by_key(|(_, seg)| seg.received) {
                stream.segments.remove(&oldest_seq);
            }
        }
        
        let seq = match packet.protocol {
            TransportProtocol::Tcp { seq, .. } => seq,
            _ => return,
        };
        
        stream.segments.insert(seq, TcpSegment {
            seq: seq,
            data: packet.payload.clone(),
            received: now,
            retransmit_count: 0,
            last_retransmit: None,
        });
    }

    pub fn cleanup_expired(&self, now: Instant) {
        let mut expired_keys = Vec::new();
        self.streams.iter().for_each(|ref_multi| {
            let stream_guard = ref_multi.value().read();
            if stream_guard.last_seen + self.timeout <= now {
                expired_keys.push(ref_multi.key().clone());
            }
        });
        for key in expired_keys {
            self.streams.remove(&key);
        }
    }

    fn find_and_remove_oldest_stream(&self) {
        let mut oldest_time = Instant::now();
        let mut oldest_key = None;

        self.streams.iter().for_each(|ref_multi| {
            let stream_guard = ref_multi.value().read();
            if stream_guard.last_seen < oldest_time {
                oldest_time = stream_guard.last_seen;
                oldest_key = Some(ref_multi.key().clone());
            }
        });

        if let Some(key) = oldest_key {
            self.streams.remove(&key);
        }
    }

    fn handle_tcp_flags(&self, stream: &mut TcpStream, packet: &DecodedPacket) {
        let (seq, tcp_flags , ack) = match &packet.protocol {
            TransportProtocol::Tcp { flags, seq ,ack,..} => (*seq, *flags, *ack),
            _ => return,
        };

        let flags = tcp_flags;
        
        // SYN 处理
        if flags & TCP_SYN != 0 {
            stream.isn = seq;
            match stream.state {
                TcpState::Closed => {
                    stream.state = TcpState::SynSent;
                    self.update_stats(StreamEvent::NewSegment,stream);
                }
                TcpState::SynSent => {
                    stream.state = TcpState::SynReceived;
                }
                _ => {
                    self.handle_error(ReassemblyError::InvalidState(stream.state), stream);
                }
            }
        }
        
        // ACK 处理
        if flags & TCP_ACK != 0 {
            match stream.state {
                TcpState::SynReceived => {
                    stream.state = TcpState::Established;
                    self.update_stats(StreamEvent::StreamEstablished, stream);
                }
                TcpState::FinWait1 => {
                    stream.state = TcpState::FinWait2;
                }
                TcpState::LastAck => {
                    stream.state = TcpState::Closed;
                    self.update_stats(StreamEvent::StreamClosed, stream);
                }
                _ => {}
            }
            stream.last_ack = ack;
        }
        
        // FIN 处理
        if flags & TCP_FIN != 0 {
            stream.fin_seq = Some(seq + packet.payload.len() as u32);
            match stream.state {
                TcpState::Established => {
                    stream.state = TcpState::FinWait1;
                }
                TcpState::SynReceived => {
                    stream.state = TcpState::FinWait1;
                }
                TcpState::CloseWait => {
                    stream.state = TcpState::LastAck;
                }
                _ => {
                    self.handle_error(ReassemblyError::InvalidState(stream.state), stream);
                }
            }
        }
        
        // RST 处理
        if flags & TCP_RST != 0 {
            stream.state = TcpState::Closed;
            self.update_stats(StreamEvent::StreamClosed, stream);
        }
    }

    fn handle_retransmission(&self, stream: &mut TcpStream, packet: &DecodedPacket) {
        let seq = match packet.protocol {
            TransportProtocol::Tcp { seq, .. } => seq,
            _ => return,
        };

        if let Some(existing_segment) = stream.segments.get_mut(&seq) {
            // 检测重传
            if existing_segment.data == packet.payload {
                existing_segment.retransmit_count += 1;
                existing_segment.last_retransmit = Some(Instant::now());
                
                // 可以添加重传统计和日志
                log::debug!("Detected retransmission for seq {}, count: {}", 
                    seq, existing_segment.retransmit_count);
            }
        }
    }

    fn handle_sack(&self, stream: &mut TcpStream, sack_blocks: &[SackBlock]) {
        for block in sack_blocks {
            // 处理 SACK 信息，可以用来优化重传决策
            stream.segments.retain(|&seq, _| 
                seq < block.start_seq || seq >= block.end_seq
            );
        }
    }

    pub fn get_stats (&self) -> StreamStats {
        let mut total_stats = StreamStats::default();
        
        // 汇总所有流的统计信息
        for stream in self.streams.iter() {
            let stream_guard = stream.value().read();
            total_stats.packet_count += stream_guard.stats.packet_count;
            total_stats.byte_count += stream_guard.stats.byte_count;
            total_stats.retransmissions += stream_guard.stats.retransmissions;
            total_stats.gaps_detected += stream_guard.stats.gaps_detected;
            total_stats.reassambled_errors += stream_guard.stats.reassambled_errors;
            total_stats.out_of_order += stream_guard.stats.out_of_order;
        }
        
        total_stats
    }

    fn update_stats(&self, event: StreamEvent, stream: &mut TcpStream) {
        match event {
            StreamEvent::Retransmission => stream.stats.retransmissions += 1,
            StreamEvent::GapDetected => stream.stats.gaps_detected += 1,
            StreamEvent::NewSegment => stream.stats.packet_count += 1,
            StreamEvent::StreamEstablished => stream.stats.packet_count += 1,
            StreamEvent::StreamClosed => stream.stats.packet_count += 1,
            StreamEvent::SegmentReassembled => stream.stats.byte_count += 1,
            StreamEvent::OutOfOrder => stream.stats.out_of_order += 1,
            StreamEvent::Error(error) => self.handle_error(error, stream),
            _ => {}
        }
    }

    fn handle_error(&self, error: ReassemblyError, stream: &mut TcpStream) {
        stream.stats.reassambled_errors += 1;
        
        match error {
            ReassemblyError::InvalidSequence(seq) => {
                log::warn!("Invalid sequence number detected: {}", seq);
                self.update_stats(StreamEvent::Error(ReassemblyError::InvalidSequence(seq)), stream);
            }
            ReassemblyError::GapTooLarge(size) => {
                log::warn!("Gap too large: {} bytes", size);
                self.update_stats(StreamEvent::Error(ReassemblyError::GapTooLarge(size)), stream);
            }
            ReassemblyError::SegmentOverlap { existing, new } => {
                log::warn!("Segment overlap detected: existing={}, new={}", existing, new);
                self.update_stats(StreamEvent::Error(ReassemblyError::SegmentOverlap { 
                    existing, 
                    new 
                }), stream);
            }
            ReassemblyError::InvalidState(state) => {
                log::warn!("Invalid TCP state transition: {:?}", state);
                self.update_stats(StreamEvent::Error(ReassemblyError::InvalidState(state)), stream);
            }
        }
    }

    fn check_memory_limits(&self, stream: &TcpStream) -> bool {
        let total_memory: usize = stream.segments.values()
            .map(|seg| seg.data.len())
            .sum();
            
        // 设置每个流的最大内存限制，例如 16MB
        total_memory <= 16 * 1024 * 1024
    }

    pub fn get_stream_count(&self) -> usize {
        self.streams.len()
    }
    
    pub async fn get_stream_stats(&self, key: String) -> Option<StreamStats> {
        self.streams.get(&key).map(|stream| stream.read().stats.clone())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;
    use crate::decode::{IpHeader, DecodedPacket};

    fn create_test_packet(seq: u32, payload: &[u8], flags: u8) -> DecodedPacket {
        DecodedPacket {
            timestamp: 0,
            ip_header: IpHeader {
                version: 4,
                ihl: 5,
                total_length: 0,
                identification: 0,
                flags: 0,
                fragment_offset: 0,
                ttl: 64,
                protocol: 6,
                checksum: 0,
                src_ip: IpAddr::from_str("192.168.1.1").unwrap(),
                dst_ip: IpAddr::from_str("192.168.1.2").unwrap(),
            },
            src_port: 1234,
            dst_port: 80,
            protocol: TransportProtocol::Tcp {
                seq,
                ack: 0,
                flags,
                window: 65535,
            },
            payload: payload.to_vec(),
        }
    }

    #[tokio::test]
    async fn test_basic_reassembly() {
        let reassembler = TcpReassembler::new(30, 1024, 1000, 100);
        
        // 测试基本重组
        let data = b"Hello, World!";
        let packet = create_test_packet(1, data, TCP_PSH | TCP_ACK);
        
        if let Some(result) = reassembler.process_packet(&packet) {
            assert_eq!(result, data);
        }
    }

    #[tokio::test]
    async fn test_out_of_order() {
        let reassembler = TcpReassembler::new(30, 1024, 1000, 100);
        
        // 发送乱序数据包
        let packet2 = create_test_packet(11, b"World!", TCP_PSH | TCP_ACK);
        let packet1 = create_test_packet(1, b"Hello, ", TCP_PSH | TCP_ACK);
        
        assert!(reassembler.process_packet(&packet2).is_none());
        if let Some(result) = reassembler.process_packet(&packet1) {
            assert_eq!(result, b"Hello, World!");
        }
    }

    #[tokio::test]
    async fn test_retransmission() {
        let reassembler = TcpReassembler::new(30, 1024, 1000, 100);
        
        // 测试重传
        let packet1 = create_test_packet(1, b"Data", TCP_PSH | TCP_ACK);
        let packet2 = create_test_packet(1, b"Data", TCP_PSH | TCP_ACK);
        
        reassembler.process_packet(&packet1);
        if let Some(_) = reassembler.process_packet(&packet2) {
            let stats = reassembler.get_stream_stats("192.168.1.1:1234-192.168.1.2:80".to_string()).await;
            assert_eq!(stats.unwrap().retransmissions, 1);
        }
    }
}