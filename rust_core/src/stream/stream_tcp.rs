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
    sack_blocks: [SackBlock; 4],
    stats: StreamStats,
    window_size: u32, // 窗口大小
    mss: u16, // 最后一个确认的最大段大小
    total_bytes: u32,
}

#[derive(Debug)]
struct TcpSegment {
    seq: u32,
    data: Box<[u8]>,
    received: Instant,
    retransmit_count: u8,
    last_retransmit: Option<Instant>,
}

pub struct TcpReassembler {
    streams: DashMap<String, Arc<RwLock<TcpStream>>>,
    timeout: Duration,
    max_gap: u32,
    max_streams: usize,
    max_segments: usize,
    stream_stats: Arc<DashMap<String, StreamStats>>,
}

impl TcpReassembler {
    pub fn new(timeout_secs: u64, max_gap: u32, max_streams: usize, max_segments: usize) -> Self {
        TcpReassembler {
            streams: DashMap::with_capacity(max_streams),
            timeout: Duration::from_secs(timeout_secs),
            max_gap,
            max_streams,
            max_segments,
            stream_stats: Arc::new(DashMap::new()),
        }
    }

    pub fn process_packet(&self, packet: &DecodedPacket) -> Option<Vec<u8>> {
        println!("[process_packet][ENTER] called, src_ip: {}, src_port: {}, dst_ip: {}, dst_port: {}, payload_len: {}", packet.ip_header.src_ip, packet.src_port, packet.ip_header.dst_ip, packet.dst_port, packet.payload.len());
        println!("[process_packet][ENTER] backtrace: {:?}", std::backtrace::Backtrace::capture());
        let (seq, ack, flags, window) = match &packet.protocol {
            TransportProtocol::Tcp { seq, ack, flags, window } => {
                (*seq, *ack, *flags, *window)
            }
            _ => return None,
        };

        let now = Instant::now();
        
        let stream_key = format!("{}:{}-{}:{}:{}", 
            packet.ip_header.src_ip, packet.src_port,
            packet.ip_header.dst_ip, packet.dst_port,
            if packet.src_port < packet.dst_port { "forward" } else { "reverse" }
        );

        println!("[process_packet] stream_key: {} seq: {} ack: {} flags: {} payload_len: {}", stream_key, seq, ack, flags, packet.payload.len());

        // 检查是否是重传包
        if let Some(stream) = self.streams.get(&stream_key) {
            let mut stream_guard = stream.write();
            println!("[process_packet] EXISTING stream, seq: {}, segments_len: {}", seq, stream_guard.segments.len());
            // 如果是重传包，更新统计信息并返回 None
            if !packet.payload.is_empty() {
                if let Some(existing_segment) = stream_guard.segments.get(&seq) {
                    if existing_segment.data == packet.payload.clone().into_boxed_slice() {
                        stream_guard.stats.retransmissions += 1;
                        self.update_stats(StreamEvent::Retransmission, &mut stream_guard);
                        println!("[process_packet] retransmission detected, seq: {}", seq);
                        return None;
                    }
                }
            }
            
            stream_guard.last_seen = now;
            stream_guard.window_size = window as u32;
            
            if !packet.payload.is_empty() {
                let packet_seq = match packet.protocol {
                    TransportProtocol::Tcp { seq, .. } => seq,
                    _ => 0,
                };
                // 新增：如果新包 seq 小于当前 seq，统计乱序
                if packet_seq < stream_guard.seq {
                    stream_guard.stats.out_of_order += 1;
                    self.update_stats(StreamEvent::OutOfOrder, &mut stream_guard);
                }
                self.add_segment(&mut stream_guard, packet, now);
                if let Some((&min_seq, _)) = stream_guard.segments.iter().next() {
                    stream_guard.seq = min_seq;
                }
                println!("[process_packet] after add_segment, segments_len: {}", stream_guard.segments.len());
            }
            
            println!("[process_packet] segments key: {:?}", stream_guard.segments.keys().collect::<Vec<_>>());
            self.handle_tcp_flags(&mut stream_guard, packet);
            let result = self.try_reassemble(&mut stream_guard);
            println!("[process_packet] try_reassemble result: {:?}", result.as_ref().map(|v| v.len()));
            return result;
        } else {
            // 新流
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
                sack_blocks: std::array::from_fn(|_| SackBlock { start_seq: 0, end_seq: 0 }),
                window_size: window as u32,
                mss: 1460,
                stats: StreamStats::default(),
                total_bytes: 0,
            }));

            if !packet.payload.is_empty() {
                let mut stream = new_stream.write();
                self.add_segment(&mut stream, packet, now);
                if let Some((&min_seq, _)) = stream.segments.iter().next() {
                    stream.seq = min_seq;
                }
                println!("[process_packet] NEW stream, after add_segment, segments_len: {}", stream.segments.len());
            }
            
            self.streams.insert(stream_key, new_stream);
            None
        }
    }

    fn try_reassemble(&self, stream: &mut TcpStream) -> Option<Vec<u8>> {
        println!("[try_reassemble][ENTER] called, stream.seq: {}, segments: {:?}", stream.seq, stream.segments.keys().collect::<Vec<_>>());
        if stream.segments.is_empty() {
            println!("[try_reassemble] segments empty, return None");
            return None;
        }

        println!("[try_reassemble] 当前 segments key: {:?}, seq: {}, total_bytes: {}", 
            stream.segments.keys().collect::<Vec<_>>(), 
            stream.seq, 
            stream.total_bytes);

        let mut reassembled = Vec::with_capacity(stream.total_bytes as usize);
        let mut next_seq = stream.seq;
        let mut out_of_order = false;

        // 获取第一个段的序列号
        if let Some((&first_seq, _)) = stream.segments.iter().next() {
            println!("[try_reassemble] first_seq: {}, next_seq: {}", first_seq, next_seq);
            
            // 如果第一个段不是期望的序列号，标记为乱序
            if first_seq != next_seq {
                println!("[try_reassemble] out_of_order detected: first_seq={}, next_seq={}", first_seq, next_seq);
                out_of_order = true;
                stream.stats.out_of_order += 1;
                return None;
            }

            // 使用 BTreeMap 的有序特性，按顺序处理段
            let mut current_seq = next_seq;
            while let Some((&seq, _)) = stream.segments.first_key_value() {
                if seq != current_seq {
                    println!("[try_reassemble][BREAK] sequence mismatch: seq={}, current_seq={}", seq, current_seq);
                    break;
                }

                if let Some(seg) = stream.segments.remove(&seq) {
                    println!("[try_reassemble][REMOVE] removed segment seq: {}, data_len: {}", 
                        seg.seq, seg.data.len());
                    reassembled.extend(&seg.data);
                    current_seq += seg.data.len() as u32;
                    stream.total_bytes -= seg.data.len() as u32;
                } else {
                    println!("[try_reassemble][ERROR] segment not found for seq: {}! break.", seq);
                    break;
                }
            }
        }

        // 清理过期的段
        let now = Instant::now();
        stream.segments.retain(|_, seg| {
            now.duration_since(seg.received) <= self.timeout
        });

        if !reassembled.is_empty() {
            println!("[try_reassemble][RETURN SOME] reassembled.len: {}", reassembled.len());
            stream.seq = next_seq + reassembled.len() as u32;
            stream.stats.byte_count += reassembled.len() as u64;
            self.update_stats(StreamEvent::SegmentReassembled, stream);
            Some(reassembled)
        } else {
            println!("[try_reassemble] reassembled empty, return None");
            None
        }
    }

    fn add_segment(&self, stream: &mut TcpStream, packet: &DecodedPacket, now: Instant) {
        let new_bytes = packet.payload.len() as u32;
        if stream.total_bytes + new_bytes > 10_000_000 { // 10MB 阈值
            // 清理最老段或拒绝新段
            return;
        }
        let seq = match packet.protocol {
            TransportProtocol::Tcp { seq, .. } => seq,
            _ => return,
        };
        if stream.segments.contains_key(&seq) {
            println!("[add_segment] WARNING: segment with seq {} already exists!", seq);
        }
        stream.total_bytes += new_bytes;
        
        if stream.segments.len() >= self.max_segments {
            if let Some((&oldest_seq, _)) = stream.segments.iter()
                .min_by_key(|(_, seg)| seg.received) {
                stream.segments.remove(&oldest_seq);
            }
        }
        stream.segments.insert(seq, TcpSegment {
            seq: seq,
            data: packet.payload.clone().into_boxed_slice(),
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
        
        match stream.state {
            TcpState::Closed => {
                if let TransportProtocol::Tcp { flags, .. } = packet.protocol {
                    if flags & TCP_SYN != 0 {
                    stream.state = TcpState::SynReceived;
                } else {
                    self.handle_error(ReassemblyError::InvalidState(stream.state), stream);
                    }
                }
            }
            TcpState::SynSent => {
                if flags & TCP_SYN != 0 {
                    stream.state = TcpState::SynReceived;
                } else {
                    self.handle_error(ReassemblyError::InvalidState(stream.state), stream);
                }
            }
            TcpState::SynReceived => {
                if flags & TCP_ACK != 0 {
                    stream.state = TcpState::Established;
                    self.update_stats(StreamEvent::StreamEstablished, stream);
                } else {
                    self.handle_error(ReassemblyError::InvalidState(stream.state), stream);
                }
            }
            TcpState::Established => {
                if flags & TCP_FIN != 0 {
                    stream.state = TcpState::FinWait1;
                }
            }
            TcpState::FinWait1 => {
                if flags & TCP_ACK != 0 {
                    stream.state = TcpState::FinWait2;
                }
            }
            TcpState::FinWait2 => {
                if flags & TCP_FIN != 0 {
                    stream.state = TcpState::LastAck;
                }
            }
            TcpState::LastAck => {
                if flags & TCP_FIN != 0 {
                    stream.state = TcpState::Closed;
                    self.update_stats(StreamEvent::StreamClosed, stream);
                }
            }
            _ => {
                self.handle_error(ReassemblyError::InvalidState(stream.state), stream);
            }
        }
        
        // ACK 处理
        if flags & TCP_ACK != 0 {
            stream.last_ack = ack;
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

        // 检查是否是重传
        if let Some(existing_segment) = stream.segments.get(&seq) {
            if existing_segment.data == packet.payload.clone().into_boxed_slice() {
                // 更新重传统计
                stream.stats.retransmissions += 1;
                self.update_stats(StreamEvent::Retransmission, stream);
                return; // 重传包直接返回，不进行重组
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
            }
            ReassemblyError::GapTooLarge(size) => {
                log::warn!("Gap too large: {} bytes", size);
            }
            ReassemblyError::SegmentOverlap { existing, new } => {
                log::warn!("Segment overlap detected: existing={}, new={}", existing, new);
            }
            ReassemblyError::InvalidState(state) => {
                log::warn!("Invalid TCP state transition: {:?}", state);
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
    
    pub fn get_stream_stats(&self, key: String) -> Option<StreamStats> {
        self.streams.get(&key).map(|stream| stream.read().stats.clone())
    }

    pub async fn shutdown(&self) -> std::result::Result<(), std::io::Error> {
        // 取消所有后台任务
        // 等待任务退出
        Ok(())
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

    #[test]
    fn test_basic_reassembly() {
        let reassembler = TcpReassembler::new(30, 1024, 1000, 100);
        
        // 测试基本重组
        let data = b"Hello, World!";
        let packet = create_test_packet(1, data, TCP_PSH | TCP_ACK);
        
        if let Some(result) = reassembler.process_packet(&packet) {
            assert_eq!(result, data);
        }
    }

    #[test]
    fn test_out_of_order() {
        println!("[test_out_of_order] 开始测试");
        let reassembler = TcpReassembler::new(30, 1024, 1000, 100);
        
        // 发送乱序数据包
        let packet2 = create_test_packet(8, b"World!", TCP_PSH | TCP_ACK);
        let packet1 = create_test_packet(1, b"Hello, ", TCP_PSH | TCP_ACK);
        
        println!("[test_out_of_order] 创建数据包完成: packet1.seq={}, packet2.seq={}", 
            match packet1.protocol {
                TransportProtocol::Tcp { seq, .. } => seq,
                _ => 0,
            },
            match packet2.protocol {
                TransportProtocol::Tcp { seq, .. } => seq,
                _ => 0,
            }
        );
        
        // 先处理第二个包
        println!("[test_out_of_order] 开始处理第二个包");
        let result2 = reassembler.process_packet(&packet2);
        println!("[test_out_of_order] 处理第二个包结果: {:?}", result2);
        assert!(result2.is_none(), "第二个包应该返回 None，因为还在等待第一个包");
        
        // 再处理第一个包
        println!("[test_out_of_order] 开始处理第一个包");
        let result1 = reassembler.process_packet(&packet1);
        println!("[test_out_of_order] 处理第一个包结果: {:?}", result1);
        assert!(result1.is_some(), "第一个包应该返回重组后的数据");
        
        if let Some(result) = result1 {
            println!("[test_out_of_order] 重组结果长度: {}", result.len());
            assert_eq!(result, b"Hello, World!", "重组结果不匹配");
        }
        
        // 验证统计信息
        let stream_key = "192.168.1.1:1234-192.168.1.2:80:reverse".to_string();
        println!("[test_out_of_order] 获取流统计信息: {}", stream_key);
        let stats = reassembler.get_stream_stats(stream_key);
        assert!(stats.is_some(), "应该能找到流统计信息");
        let stats = stats.unwrap();
        println!("[test_out_of_order] 流统计信息: {:?}", stats);
        assert!(stats.out_of_order > 0, "应该检测到乱序包");
        
        println!("[test_out_of_order] 测试完成");
    }

    #[test]
    fn test_retransmission() {
        let reassembler = TcpReassembler::new(30, 1024, 1000, 100);
        
        // 测试重传
        let packet1 = create_test_packet(1, b"Data", TCP_PSH | TCP_ACK);
        let packet2 = create_test_packet(1, b"Data", TCP_PSH | TCP_ACK);
        
        // 处理第一个包
        let result1 = reassembler.process_packet(&packet1);
        println!("处理第一个包结果: {:?}", result1);
        assert!(result1.is_some());
        
        // 处理重传包
        let result2 = reassembler.process_packet(&packet2);
        println!("处理重传包结果: {:?}", result2);
        assert!(result2.is_none()); // 重传包应该返回 None
        
        // 验证重传统计
        let stream_key = "192.168.1.1:1234-192.168.1.2:80:reverse".to_string();
        let stats = reassembler.get_stream_stats(stream_key);
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.retransmissions, 1);
    }

    #[test]
    fn test_edge_cases() {
        // 测试最大序列号
        // 测试序列号回绕
        // 测试超大窗口
        // 测试零窗口
    }
}

fn is_seq_after(a: u32, b: u32) -> bool {
    (a > b && a - b < 0x80000000) || (a < b && b - a > 0x80000000)
}