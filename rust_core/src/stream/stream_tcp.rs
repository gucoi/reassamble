use std::collections::{BTreeMap};
use tokio::time::{Duration, Instant};
use super::super::decode::DecodedPacket;
use parking_lot::RwLock;  // 使用 parking_lot 提供的更高效的读写锁
use dashmap::DashMap;     // 使用 DashMap 替代 HashMap
use std::sync::Arc;
use super::super::stream::StreamStats;
use crate::decode::TransportProtocol;
use crate::memory::MemoryBlock;
use bytes::BytesMut;

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

#[derive(Debug, Clone, Copy, PartialEq)]
struct SackBlock {
    start_seq: u32,
    end_seq: u32,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
struct TcpSegment {
    seq: u32,
    data: MemoryBlock,
    received: Instant,
    retransmit_count: u8,
    last_retransmit: Option<Instant>,
}

impl TcpSegment {
    fn new(seq: u32, data: BytesMut, received: Instant) -> Self {
        let mut block = MemoryBlock::new(data.len());
        {
            let mut block_data = block.lock();
            block_data.extend_from_slice(&data);
        }
        
        Self {
            seq,
            data: block,
            received,
            retransmit_count: 0,
            last_retransmit: None,
        }
    }
}

impl Drop for TcpSegment {
    fn drop(&mut self) {
        self.data.mark_free();
    }
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
        log::debug!("处理数据包: src_ip={}, src_port={}, dst_ip={}, dst_port={}, payload_len={}", 
            packet.ip_header.source_ip, packet.src_port, 
            packet.ip_header.dest_ip, packet.dst_port, 
            packet.payload.len());

        let (seq, ack, flags, window) = match &packet.protocol {
            TransportProtocol::TCP { seq, ack, flags, window } => {
                (*seq, *ack, *flags, *window)
            }
            _ => return None,
        };

        let now = Instant::now();
        
        let stream_key = format!("{}:{}-{}:{}:{}", 
            packet.ip_header.source_ip, packet.src_port,
            packet.ip_header.dest_ip, packet.dst_port,
            if packet.src_port < packet.dst_port { "forward" } else { "reverse" }
        );

        log::debug!("流标识: {}, seq={}, ack={}, flags={}, payload_len={}", 
            stream_key, seq, ack, flags, packet.payload.len());

        // 检查是否是重传包
        if let Some(stream) = self.streams.get(&stream_key) {
            let mut stream_guard = stream.write();
            
            // 添加状态超时检查
            self.check_state_timeout(&mut stream_guard, now);
            
            log::debug!("处理已存在的流, seq={}, segments_len={}", seq, stream_guard.segments.len());
            
            // 如果是重传包，更新统计信息并返回 None
            if !packet.payload.is_empty() {
                let is_retransmission = {
                    if let Some(existing_segment) = stream_guard.segments.get(&seq) {
                        let existing_data = existing_segment.data.lock();
                        existing_data.as_ref() == &packet.payload
                    } else {
                        false
                    }
                };

                if is_retransmission {
                    stream_guard.stats.retransmissions += 1;
                    self.update_stats(StreamEvent::Retransmission, &mut stream_guard);
                    // 更新全局统计信息
                    if let Some(mut stats) = self.stream_stats.get_mut(&stream_key) {
                        stats.retransmissions += 1;
                    }
                    log::debug!("检测到重传包, seq={}", seq);
                    return None;
                }
            }
            
            stream_guard.last_seen = now;
            stream_guard.window_size = window as u32;
            
            if !packet.payload.is_empty() {
                let packet_seq = match packet.protocol {
                    TransportProtocol::TCP { seq, .. } => seq,
                    _ => 0,
                };
                // 新增：如果新包 seq 小于当前 seq，统计乱序
                if packet_seq < stream_guard.seq {
                    stream_guard.stats.out_of_order += 1;
                    self.update_stats(StreamEvent::OutOfOrder, &mut stream_guard);
                    // 更新全局统计信息
                    if let Some(mut stats) = self.stream_stats.get_mut(&stream_key) {
                        stats.out_of_order += 1;
                    }
                }
                self.add_segment(&mut stream_guard, packet, now);
                if let Some((&min_seq, _)) = stream_guard.segments.iter().next() {
                    stream_guard.seq = min_seq;
                }
                log::debug!("添加段后, segments_len={}", stream_guard.segments.len());
            }
            
            log::debug!("当前段序列号: {:?}", stream_guard.segments.keys().collect::<Vec<_>>());
            self.handle_tcp_flags(&mut stream_guard, packet);
            let result = self.try_reassemble(&mut stream_guard);
            log::debug!("重组结果长度: {:?}", result.as_ref().map(|v| v.len()));
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
                state: TcpState::SynSent,
                isn: seq,
                fin_seq: None,
                sack_blocks: std::array::from_fn(|_| SackBlock { start_seq: 0, end_seq: 0 }),
                window_size: window as u32,
                mss: 1460,
                stats: StreamStats::default(),
                total_bytes: 0,
            }));

            // 为新流创建统计信息
            self.stream_stats.insert(stream_key.clone(), StreamStats::default());

            if !packet.payload.is_empty() {
                let mut stream = new_stream.write();
                self.add_segment(&mut stream, packet, now);
                if let Some((&min_seq, _)) = stream.segments.iter().next() {
                    stream.seq = min_seq;
                }
                log::debug!("新流添加段后, segments_len={}", stream.segments.len());
            }
            
            self.streams.insert(stream_key, new_stream);
            None
        }
    }

    fn try_reassemble(&self, stream: &mut TcpStream) -> Option<Vec<u8>> {
        log::debug!("尝试重组, stream.seq={}, segments={:?}", 
            stream.seq, stream.segments.keys().collect::<Vec<_>>());
            
        if stream.segments.is_empty() {
            log::debug!("段为空，返回 None");
            return None;
        }

        log::debug!("当前段序列号: {:?}, seq={}, total_bytes={}", 
            stream.segments.keys().collect::<Vec<_>>(), 
            stream.seq, 
            stream.total_bytes);

        let mut reassembled = Vec::with_capacity(stream.total_bytes as usize);
        let mut next_seq = stream.seq;
        let mut out_of_order = false;

        // 获取第一个段的序列号
        if let Some((&first_seq, _)) = stream.segments.iter().next() {
            log::debug!("first_seq={}, next_seq={}", first_seq, next_seq);
            
            // 如果第一个段不是期望的序列号，检查是否在 SACK 块中
            if first_seq != next_seq {
                if !stream.is_seq_sacked(first_seq) {
                    log::warn!("检测到乱序: first_seq={}, next_seq={}", first_seq, next_seq);
                    out_of_order = true;
                    stream.stats.out_of_order += 1;
                    self.update_stats(StreamEvent::OutOfOrder, stream);
                    return None;
                }
            }

            // 使用 BTreeMap 的有序特性，按顺序处理段
            let mut current_seq = next_seq;
            while let Some((&seq, _)) = stream.segments.first_key_value() {
                if seq != current_seq && !stream.is_seq_sacked(seq) {
                    log::warn!("序列号不匹配: seq={}, current_seq={}", seq, current_seq);
                    let gap_size = seq - current_seq;
                    if gap_size > self.max_gap {
                        self.handle_error(ReassemblyError::GapTooLarge(gap_size), stream);
                    }
                    break;
                }

                if let Some(seg) = stream.segments.remove(&seq) {
                    log::debug!("移除段: seq={}, data_len={}", seg.seq, seg.data.len());
                    let data = seg.data.lock();
                    reassembled.extend_from_slice(data.as_ref());
                    current_seq += data.len() as u32;
                    stream.total_bytes -= data.len() as u32;
                } else {
                    log::error!("未找到段: seq={}", seq);
                    self.handle_error(ReassemblyError::InvalidSequence(seq), stream);
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
            log::debug!("重组完成, 长度={}", reassembled.len());
            stream.seq = next_seq + reassembled.len() as u32;
            stream.stats.byte_count += reassembled.len() as u64;
            self.update_stats(StreamEvent::SegmentReassembled, stream);
            Some(reassembled)
        } else {
            log::debug!("重组结果为空");
            None
        }
    }

    fn add_segment(&self, stream: &mut TcpStream, packet: &DecodedPacket, now: Instant) {
        let new_bytes = packet.payload.len() as u32;
        
        // 检查窗口大小限制
        if stream.window_size > 0 && new_bytes > stream.window_size {
            self.handle_error(ReassemblyError::GapTooLarge(new_bytes), stream);
            return;
        }
        
        if stream.total_bytes + new_bytes > 10_000_000 { // 10MB 阈值
            self.handle_error(ReassemblyError::GapTooLarge(new_bytes), stream);
            return;
        }
        
        let seq = match packet.protocol {
            TransportProtocol::TCP { seq, .. } => seq,
            _ => return,
        };
        
        // 检查序列号是否有效
        if !is_seq_after(seq, stream.seq) && seq != stream.seq {
            self.handle_error(ReassemblyError::InvalidSequence(seq), stream);
            return;
        }
        
        if stream.segments.contains_key(&seq) {
            log::warn!("段已存在: seq={}", seq);
            self.handle_error(ReassemblyError::SegmentOverlap { 
                existing: seq, 
                new: seq 
            }, stream);
            return;
        }
        
        stream.total_bytes += new_bytes;
        
        // 检查段大小是否超过 MSS
        if new_bytes > stream.mss as u32 {
            log::warn!("段大小超过 MSS: size={}, mss={}", new_bytes, stream.mss);
        }
        
        if stream.segments.len() >= self.max_segments {
            if let Some((&oldest_seq, _)) = stream.segments.iter()
                .min_by_key(|(_, seg)| seg.received) {
                stream.segments.remove(&oldest_seq);
            }
        }
        
        let segment = TcpSegment::new(seq, packet.payload.clone(), now);
        stream.segments.insert(seq, segment);
        
        // 添加新段事件
        self.update_stats(StreamEvent::NewSegment, stream);
        
        // 检查是否有间隙
        if let Some((&next_seq, _)) = stream.segments.iter().next() {
            if next_seq > stream.seq + 1 {
                let gap_size = next_seq - stream.seq;
                if gap_size > self.max_gap {
                    self.handle_error(ReassemblyError::GapTooLarge(gap_size), stream);
                } else {
                    self.update_stats(StreamEvent::GapDetected, stream);
                }
            }
        }
    }

    pub fn cleanup_expired(&self, now: Instant) {
        let mut expired_keys = Vec::new();
        self.streams.iter().for_each(|ref_multi| {
            let mut stream_guard = ref_multi.value().write();
            if stream_guard.last_seen + self.timeout <= now {
                expired_keys.push(ref_multi.key().clone());
                // 清理过期的统计信息
                self.stream_stats.remove(ref_multi.key());
            } else {
                // 清理过期的段
                stream_guard.segments.retain(|_, seg| {
                    // 如果段被重传超过3次，或者最后一次重传超过30秒，则删除
                    if seg.retransmit_count > 3 {
                        return false;
                    }
                    if let Some(last_retransmit) = seg.last_retransmit {
                        if now.duration_since(last_retransmit) > Duration::from_secs(30) {
                            return false;
                        }
                    }
                    now.duration_since(seg.received) <= self.timeout
                });
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

    fn check_state_timeout(&self, stream: &mut TcpStream, now: Instant) {
        match stream.state {
            TcpState::FinWait2 => {
                if now - stream.last_seen > Duration::from_secs(60) {
                    stream.state = TcpState::Closed;
                    self.update_stats(StreamEvent::StreamClosed, stream);
                }
            }
            TcpState::TimeWait => {
                if now - stream.last_seen > Duration::from_secs(2 * 60) { // 2MSL
                    stream.state = TcpState::Closed;
                    self.update_stats(StreamEvent::StreamClosed, stream);
                }
            }
            _ => {}
        }
    }

    fn handle_tcp_flags(&self, stream: &mut TcpStream, packet: &DecodedPacket) {
        let (seq, tcp_flags, ack) = match &packet.protocol {
            TransportProtocol::TCP { flags, seq, ack, .. } => (*seq, *flags, *ack),
            _ => return,
        };

        let flags = tcp_flags;
        
        match stream.state {
            TcpState::Closed => {
                if flags & TCP_SYN != 0 {
                    stream.state = TcpState::SynReceived;
                } else {
                    self.handle_error(ReassemblyError::InvalidState(stream.state), stream);
                }
            }
            TcpState::SynSent => {
                if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
                    stream.state = TcpState::Established;
                    self.update_stats(StreamEvent::StreamEstablished, stream);
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
                    // 收到对方的 FIN，进入 CloseWait 状态
                    stream.state = TcpState::CloseWait;
                    stream.fin_seq = Some(seq);
                    // 验证 FIN 序列号
                    if let Some(fin_seq) = stream.fin_seq {
                        if fin_seq != seq {
                            log::warn!("WARNING: FIN sequence number mismatch: expected {}, got {}", fin_seq, seq);
                        }
                    }
                } else if flags & TCP_ACK != 0 {
                    // 主动关闭连接
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
                    stream.state = TcpState::Closing;
                    // 验证 FIN 序列号
                    if let Some(fin_seq) = stream.fin_seq {
                        if fin_seq != seq {
                            log::warn!("WARNING: FIN sequence number mismatch: expected {}, got {}", fin_seq, seq);
                        }
                    }
                }
            }
            TcpState::CloseWait => {
                // 在 CloseWait 状态下，如果本地应用发送了 FIN，则进入 LastAck 状态
                if flags & TCP_FIN != 0 {
                    stream.state = TcpState::LastAck;
                }
            }
            TcpState::Closing => {
                if flags & TCP_ACK != 0 {
                    stream.state = TcpState::TimeWait;
                }
            }
            TcpState::LastAck => {
                if flags & TCP_ACK != 0 {
                    stream.state = TcpState::Closed;
                    self.update_stats(StreamEvent::StreamClosed, stream);
                }
            }
            TcpState::TimeWait => {
                // TimeWait 状态由超时检查处理
            }
        }
        
        // ACK 处理
        if flags & TCP_ACK != 0 {
            stream.last_ack = ack;
            // 更新窗口大小
            if let TransportProtocol::TCP { window, .. } = packet.protocol {
                stream.window_size = window as u32;
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
            TransportProtocol::TCP { seq, .. } => seq,
            _ => return,
        };

        // 检查是否是重传
        let is_retransmission = {
            if let Some(existing_segment) = stream.segments.get(&seq) {
                let existing_data = existing_segment.data.lock();
                existing_data.as_ref() == &packet.payload
            } else {
                false
            }
        };

        if is_retransmission {
            // 更新重传计数和时间
            if let Some(segment) = stream.segments.remove(&seq) {
                let mut updated_segment = segment;
                updated_segment.retransmit_count += 1;
                updated_segment.last_retransmit = Some(Instant::now());
                stream.segments.insert(seq, updated_segment);
            }
            
            stream.stats.retransmissions += 1;
            self.update_stats(StreamEvent::Retransmission, stream);
        }
    }

    fn handle_sack(&self, stream: &mut TcpStream, sack_blocks: &[SackBlock]) {
        for &block in sack_blocks {
            if block.start_seq != 0 && block.end_seq != 0 {
                stream.update_sack_blocks(block);
            }
        }

        // 使用 SACK 信息优化段管理
        let sacked_seqs: Vec<u32> = stream.segments.keys()
            .filter(|&&seq| stream.is_seq_sacked(seq))
            .cloned()
            .collect();
            
        for seq in sacked_seqs {
            if let Some(seg) = stream.segments.remove(&seq) {
                // 如果段在 SACK 块内，保留它
                stream.segments.insert(seq, seg);
            }
        }
        
        // 删除已确认的段
        stream.segments.retain(|&seq, _| {
            seq >= stream.last_ack
        });
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
            StreamEvent::Retransmission => {
                stream.stats.retransmissions += 1;
                log::info!("检测到重传包");
            }
            StreamEvent::GapDetected => {
                stream.stats.gaps_detected += 1;
                log::info!("检测到数据间隙");
            }
            StreamEvent::NewSegment => {
                stream.stats.packet_count += 1;
                log::info!("收到新数据段");
            }
            StreamEvent::StreamEstablished => {
                stream.stats.packet_count += 1;
                log::info!("TCP 连接已建立");
            }
            StreamEvent::StreamClosed => {
                stream.stats.packet_count += 1;
                log::info!("TCP 连接已关闭");
            }
            StreamEvent::SegmentReassembled => {
                stream.stats.byte_count += 1;
                log::info!("数据段重组完成");
            }
            StreamEvent::OutOfOrder => {
                stream.stats.out_of_order += 1;
                log::info!("检测到乱序包");
            }
            StreamEvent::Error(error) => {
                log::error!("重组错误: {:?}", error);
                self.handle_error(error, stream);
            }
        }
    }

    fn handle_error(&self, error: ReassemblyError, stream: &mut TcpStream) {
        stream.stats.reassambled_errors += 1;
        match error {
            ReassemblyError::InvalidSequence(seq) => {
                log::warn!("无效的序列号: {}", seq);
            }
            ReassemblyError::GapTooLarge(size) => {
                log::warn!("数据间隙过大: {} 字节", size);
            }
            ReassemblyError::SegmentOverlap { existing, new } => {
                log::warn!("数据段重叠: 现有序列号={}, 新序列号={}", existing, new);
            }
            ReassemblyError::InvalidState(state) => {
                log::warn!("无效的 TCP 状态转换: {:?}", state);
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

impl TcpStream {
    // 添加新方法
    fn update_sack_blocks(&mut self, new_block: SackBlock) {
        // 清理过期的 SACK 块
        self.cleanup_sack_blocks();
        
        // 尝试合并相邻的 SACK 块
        for i in 0..self.sack_blocks.len() {
            if self.sack_blocks[i].start_seq == 0 && self.sack_blocks[i].end_seq == 0 {
                // 找到空槽位，直接插入
                self.sack_blocks[i] = new_block;
                return;
            }
            
            // 尝试合并相邻的块
            if new_block.end_seq == self.sack_blocks[i].start_seq {
                self.sack_blocks[i].start_seq = new_block.start_seq;
                return;
            }
            if new_block.start_seq == self.sack_blocks[i].end_seq {
                self.sack_blocks[i].end_seq = new_block.end_seq;
                return;
            }
        }
    }
    
    fn cleanup_sack_blocks(&mut self) {
        // 清理已经被确认的 SACK 块
        for block in &mut self.sack_blocks {
            if block.end_seq <= self.last_ack {
                *block = SackBlock { start_seq: 0, end_seq: 0 };
            }
        }
    }
    
    fn is_seq_sacked(&self, seq: u32) -> bool {
        self.sack_blocks.iter().any(|block| 
            block.start_seq != 0 && 
            block.end_seq != 0 && 
            seq >= block.start_seq && 
            seq < block.end_seq
        )
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
                tos: 0,
                total_length: 0,
                identification: 0,
                flags: 0,
                fragment_offset: 0,
                ttl: 64,
                protocol: 6,
                header_checksum: 0,
                source_ip: u32::from_be_bytes([192,168,1,1]),
                dest_ip: u32::from_be_bytes([192,168,1,2]),
            },
            src_port: 1234,
            dst_port: 80,
            protocol: TransportProtocol::TCP {
                seq,
                ack: 0,
                flags,
                window: 65535,
            },
            payload: BytesMut::from(payload),
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
                TransportProtocol::TCP { seq, .. } => seq,
                _ => 0,
            },
            match packet2.protocol {
                TransportProtocol::TCP { seq, .. } => seq,
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