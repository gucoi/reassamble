use crate::{
    decode::{decode_packet, TransportProtocol, DecodedPacket, DecodeContext},
    defrag::{IpDefragmenter, FragmentPolicy},
    stream::ShardedTcpReassembler,
    SafePacket,
    error::Result,
    error::ReassembleError,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{error, debug, trace};
use super::worker::WorkerPool;
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use bytes::BytesMut;
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};

/// 处理阶段枚举，参考Suricata的pipeline设计
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcessingStage {
    /// 解码阶段
    Decode,
    /// IP分片重组阶段
    Defragment,
    /// TCP流重组阶段
    StreamReassembly,
    /// 应用层处理阶段
    Application,
    /// 完成阶段
    Complete,
}

/// 处理结果，参考Suricata的Packet结构
#[derive(Debug, Clone)]
pub struct ProcessingResult {
    /// 处理阶段
    pub stage: ProcessingStage,
    /// 重组后的数据
    pub data: Option<Vec<u8>>,
    /// 处理时间
    pub processing_time: Duration,
    /// 错误信息
    pub error: Option<String>,
    /// 统计信息
    pub stats: PacketStats,
}

impl ProcessingResult {
    pub fn new(stage: ProcessingStage) -> Self {
        Self {
            stage,
            data: None,
            processing_time: Duration::ZERO,
            error: None,
            stats: PacketStats::default(),
        }
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    pub fn with_processing_time(mut self, time: Duration) -> Self {
        self.processing_time = time;
        self
    }
}

/// 数据包统计信息，参考Suricata的统计设计
#[derive(Debug, Clone, Default)]
pub struct PacketStats {
    /// 数据包大小
    pub packet_size: usize,
    /// 协议类型
    pub protocol: u8,
    /// 是否为分片
    pub is_fragment: bool,
    /// 分片偏移量
    pub fragment_offset: u16,
    /// 是否为TCP流
    pub is_tcp_stream: bool,
    /// 处理延迟
    pub latency: Duration,
}

/// 处理器配置，参考Suricata的配置系统
#[derive(Debug, Clone)]
pub struct ProcessorConfig {
    /// 批处理大小
    pub batch_size: usize,
    /// 分片重组策略
    pub fragment_policy: FragmentPolicy,
    /// 分片超时时间
    pub fragment_timeout: Duration,
    /// 最大分片组数量
    pub max_fragment_groups: usize,
    /// 是否启用详细日志
    pub verbose_logging: bool,
    /// 性能监控间隔
    pub stats_interval: Duration,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self {
            batch_size: 1000,
            fragment_policy: FragmentPolicy::First,
            fragment_timeout: Duration::from_secs(30),
            max_fragment_groups: 10000,
            verbose_logging: false,
            stats_interval: Duration::from_secs(60),
        }
    }
}

/// 批量数据包结构，参考Suricata的batch处理
#[derive(Debug)]
pub struct BatchPacket {
    pub packets: Vec<SafePacket>,
    pub timestamp: u64,
    pub batch_id: u64,
}

impl BatchPacket {
    pub fn new(packets: Vec<SafePacket>, timestamp: u64, batch_id: u64) -> Self {
        Self { packets, timestamp, batch_id }
    }

    pub fn with_capacity(capacity: usize, timestamp: u64, batch_id: u64) -> Self {
        Self {
            packets: Vec::with_capacity(capacity),
            timestamp,
            batch_id,
        }
    }

    pub fn add_packet(&mut self, packet: SafePacket) {
        self.packets.push(packet);
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

/// 处理器统计信息，参考Suricata的统计系统
#[derive(Debug, Default)]
pub struct ProcessorStats {
    /// 总处理数据包数
    pub total_packets: AtomicUsize,
    /// 成功处理数据包数
    pub successful_packets: AtomicUsize,
    /// 分片重组数据包数
    pub fragmented_packets: AtomicUsize,
    /// TCP流重组数据包数
    pub tcp_stream_packets: AtomicUsize,
    /// 处理失败数据包数
    pub failed_packets: AtomicUsize,
    /// 总处理时间
    pub total_processing_time: AtomicUsize, // 纳秒
    /// 平均处理延迟
    pub avg_latency: AtomicUsize, // 纳秒
    /// 最大处理延迟
    pub max_latency: AtomicUsize, // 纳秒
    /// 批处理数量
    pub batch_count: AtomicUsize,
    /// 最后更新时间
    pub last_update: AtomicUsize, // Unix时间戳
}

impl ProcessorStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_packet(&self, processing_time: Duration, success: bool) {
        let time_ns = processing_time.as_nanos() as usize;
        
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_processing_time.fetch_add(time_ns, Ordering::Relaxed);
        
        if success {
            self.successful_packets.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_packets.fetch_add(1, Ordering::Relaxed);
        }

        // 更新平均延迟
        let total = self.total_packets.load(Ordering::Relaxed);
        let total_time = self.total_processing_time.load(Ordering::Relaxed);
        if total > 0 {
            self.avg_latency.store(total_time / total, Ordering::Relaxed);
        }

        // 更新最大延迟
        let current_max = self.max_latency.load(Ordering::Relaxed);
        if time_ns > current_max {
            self.max_latency.store(time_ns, Ordering::Relaxed);
        }

        // 更新时间戳
        self.last_update.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize,
            Ordering::Relaxed,
        );
    }

    pub fn record_fragment(&self) {
        self.fragmented_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tcp_stream(&self) {
        self.tcp_stream_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_batch(&self) {
        self.batch_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_snapshot(&self) -> ProcessorStatsSnapshot {
        ProcessorStatsSnapshot {
            total_packets: self.total_packets.load(Ordering::Relaxed),
            successful_packets: self.successful_packets.load(Ordering::Relaxed),
            fragmented_packets: self.fragmented_packets.load(Ordering::Relaxed),
            tcp_stream_packets: self.tcp_stream_packets.load(Ordering::Relaxed),
            failed_packets: self.failed_packets.load(Ordering::Relaxed),
            total_processing_time: Duration::from_nanos(self.total_processing_time.load(Ordering::Relaxed) as u64),
            avg_latency: Duration::from_nanos(self.avg_latency.load(Ordering::Relaxed) as u64),
            max_latency: Duration::from_nanos(self.max_latency.load(Ordering::Relaxed) as u64),
            batch_count: self.batch_count.load(Ordering::Relaxed),
            last_update: self.last_update.load(Ordering::Relaxed),
        }
    }

    pub fn throughput(&self) -> f64 {
        let total_time = self.total_processing_time.load(Ordering::Relaxed) as f64 / 1_000_000_000.0; // 转换为秒
        if total_time > 0.0 {
            self.total_packets.load(Ordering::Relaxed) as f64 / total_time
        } else {
            0.0
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.total_packets.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        self.successful_packets.load(Ordering::Relaxed) as f64 / total as f64
    }
}

/// 处理器统计快照
#[derive(Debug, Clone)]
pub struct ProcessorStatsSnapshot {
    pub total_packets: usize,
    pub successful_packets: usize,
    pub fragmented_packets: usize,
    pub tcp_stream_packets: usize,
    pub failed_packets: usize,
    pub total_processing_time: Duration,
    pub avg_latency: Duration,
    pub max_latency: Duration,
    pub batch_count: usize,
    pub last_update: usize,
}

/// 高性能数据包处理器，参考Suricata的PacketProcessor设计
pub struct PacketProcessor {
    /// 配置
    config: ProcessorConfig,
    /// IP分片重组器
    defragmenter: Arc<RwLock<IpDefragmenter>>,
    /// TCP流重组器
    reassembler: Arc<ShardedTcpReassembler>,
    /// 工作线程池
    worker_pool: Arc<WorkerPool>,
    /// 统计信息
    stats: Arc<ProcessorStats>,
    /// 批处理ID计数器
    batch_id_counter: AtomicUsize,
    /// 活跃批处理数量
    active_batches: AtomicUsize,
}

impl PacketProcessor {
    /// 创建新的处理器实例
    pub fn new(reassembler: Arc<ShardedTcpReassembler>) -> Self {
        Self::with_config(reassembler, ProcessorConfig::default())
    }

    /// 使用指定配置创建处理器
    pub fn with_config(reassembler: Arc<ShardedTcpReassembler>, config: ProcessorConfig) -> Self {
        let defragmenter = Arc::new(RwLock::new(
            IpDefragmenter::with_policy(config.fragment_policy)
        ));
        
        let worker_pool = Arc::new(WorkerPool::new(reassembler.clone()));
        
        Self {
            config,
            defragmenter,
            reassembler,
            worker_pool,
            stats: Arc::new(ProcessorStats::new()),
            batch_id_counter: AtomicUsize::new(0),
            active_batches: AtomicUsize::new(0),
        }
    }

    /// 处理单个数据包，使用WorkerPool异步处理
    pub async fn process_packet(&self, packet: &SafePacket) -> Result<ProcessingResult> {
        let start_time = Instant::now();
        let mut result = ProcessingResult::new(ProcessingStage::Decode);

        trace!("开始处理数据包: timestamp={}, data_len={}", 
               packet.timestamp, packet.data.len());

        // 先尝试解码数据包
        match decode_packet(&mut DecodeContext::new(), packet, &packet.data[..]) {
            Ok(decoded) => {
                result.stats.packet_size = packet.data.len();
                result.stats.protocol = decoded.ip_header.protocol;

                // 检查是否为分片包
                if decoded.ip_header.more_fragments || decoded.ip_header.fragment_offset > 0 {
                    result.stats.is_fragment = true;
                    result.stats.fragment_offset = decoded.ip_header.fragment_offset;
                    self.stats.record_fragment();

                    result.stage = ProcessingStage::Defragment;
                    let mut defrag = self.defragmenter.write().await;
                    match defrag.process_packet(&decoded) {
                        Ok(Some(reassembled)) => {
                            debug!("IP分片重组完成，处理重组后的数据包");
                            // 分片重组完成，直接返回重组后的数据
                            result.stage = ProcessingStage::Complete;
                            result.data = Some(reassembled.payload);
                        }
                        Ok(None) => {
                            trace!("IP分片重组未完成，等待更多分片");
                            // 分片重组未完成，继续等待
                        }
                        Err(e) => {
                            error!("IP分片重组失败: {:?}", e);
                            result.error = Some(format!("IP分片重组失败: {:?}", e));
                        }
                    }
                } else {
                    // 非分片包，使用WorkerPool异步处理
                    match self.worker_pool.submit(packet.clone()).await {
                        Ok(_) => {
                            debug!("数据包已提交到WorkerPool进行异步处理");
                            result.stage = ProcessingStage::Complete;
                        }
                        Err(e) => {
                            error!("WorkerPool提交失败: {:#}", e);
                            result.error = Some(format!("WorkerPool提交失败: {:#}", e));
                            return Err(ReassembleError::StreamError(format!("WorkerPool提交失败: {:#}", e)));
                        }
                    }
                }
            },
            Err(e) => {
                let error_msg = format!("数据包解码失败: {:?}", e);
                error!("{}", error_msg);
                result.error = Some(error_msg);
            }
        }

        result.processing_time = start_time.elapsed();
        self.stats.record_packet(start_time.elapsed(), result.error.is_none());
        Ok(result)
    }

    /// 批量处理数据包，参考Suricata的batch processing
    pub async fn process_batch(&self, batch: BatchPacket) -> Result<Vec<ProcessingResult>> {
        let start_time = Instant::now();
        self.active_batches.fetch_add(1, Ordering::Relaxed);
        self.stats.record_batch();

        debug!("开始批量处理: batch_id={}, packet_count={}", 
               batch.batch_id, batch.packets.len());

        let mut results = Vec::with_capacity(batch.packets.len());
        let mut defrag = self.defragmenter.write().await;

        // 阶段1: 批量解码和分片处理
        for packet in &batch.packets {
            let result = match decode_packet(&mut DecodeContext::new(), packet, &packet.data[..]) {
                Ok(decoded) => {
                    let mut packet_result = ProcessingResult::new(ProcessingStage::Decode);
                    packet_result.stats.packet_size = packet.data.len();
                    packet_result.stats.protocol = decoded.ip_header.protocol;

                    // 检查是否为分片包
                    if decoded.ip_header.more_fragments || decoded.ip_header.fragment_offset > 0 {
                        packet_result.stats.is_fragment = true;
                        packet_result.stats.fragment_offset = decoded.ip_header.fragment_offset;
                        self.stats.record_fragment();

                        packet_result.stage = ProcessingStage::Defragment;
                        match defrag.process_packet(&decoded) {
                            Ok(Some(reassembled)) => {
                                debug!("IP分片重组完成，处理重组后的数据包");
                                // 处理重组后的数据包
                                match &reassembled.protocol {
                                    TransportProtocol::TCP { .. } => {
                                        packet_result.stats.is_tcp_stream = true;
                                        self.stats.record_tcp_stream();
                                        
                                        packet_result.stage = ProcessingStage::StreamReassembly;
                                        let stream_result = self.reassembler.process_packet(&reassembled);
                                        match stream_result {
                                            Ok(Some(data)) => {
                                                packet_result.stage = ProcessingStage::Complete;
                                                packet_result.data = Some(data);
                                            },
                                            Ok(None) => {
                                                packet_result.stage = ProcessingStage::StreamReassembly;
                                            },
                                            Err(e) => {
                                                error!("TCP流重组失败: {:?}", e);
                                                packet_result.error = Some(format!("TCP流重组失败: {:?}", e));
                                            }
                                        }
                                    },
                                    _ => {
                                        packet_result.stage = ProcessingStage::Application;
                                        packet_result.data = Some(reassembled.payload);
                                    }
                                }
                            }
                            Ok(None) => {
                                trace!("IP分片重组未完成，等待更多分片");
                                // 分片重组未完成，继续等待
                            }
                            Err(e) => {
                                error!("IP分片重组失败: {:?}", e);
                                packet_result.error = Some(format!("IP分片重组失败: {:?}", e));
                            }
                        }
                    } else {
                        // 非分片包
                        match &decoded.protocol {
                            TransportProtocol::TCP { .. } => {
                                packet_result.stats.is_tcp_stream = true;
                                self.stats.record_tcp_stream();
                                
                                packet_result.stage = ProcessingStage::StreamReassembly;
                                let stream_result = self.reassembler.process_packet(&decoded);
                                match stream_result {
                                    Ok(Some(data)) => {
                                        packet_result.stage = ProcessingStage::Complete;
                                        packet_result.data = Some(data);
                                    },
                                    Ok(None) => {
                                        packet_result.stage = ProcessingStage::StreamReassembly;
                                    },
                                    Err(e) => {
                                        error!("TCP流重组失败: {:?}", e);
                                        packet_result.error = Some(format!("TCP流重组失败: {:?}", e));
                                    }
                                }
                            },
                            _ => {
                                packet_result.stage = ProcessingStage::Application;
                                packet_result.data = Some(decoded.payload);
                            }
                        }
                    }
                    packet_result
                },
                Err(e) => {
                    let error_msg = format!("数据包解码失败: {:?}", e);
                    error!("{}", error_msg);
                    ProcessingResult::new(ProcessingStage::Decode).with_error(error_msg)
                }
            };
            results.push(result);
        }

        drop(defrag);

        self.active_batches.fetch_sub(1, Ordering::Relaxed);
        
        let total_time = start_time.elapsed();
        debug!("批量处理完成: batch_id={}, 处理时间={:?}", 
               batch.batch_id, total_time);

        Ok(results)
    }

    /// 创建新的批处理
    pub fn create_batch(&self, timestamp: u64) -> BatchPacket {
        let batch_id = self.batch_id_counter.fetch_add(1, Ordering::Relaxed) as u64;
        BatchPacket::with_capacity(self.config.batch_size, timestamp, batch_id)
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> ProcessorStatsSnapshot {
        self.stats.get_snapshot()
    }

    /// 获取活跃批处理数量
    pub fn get_active_batches(&self) -> usize {
        self.active_batches.load(Ordering::Relaxed)
    }

    /// 更新配置
    pub async fn update_config(&mut self, config: ProcessorConfig) {
        self.config = config.clone();
        
        // 更新分片重组器配置
        let mut defrag = self.defragmenter.write().await;
        *defrag = IpDefragmenter::with_policy(config.fragment_policy);
        defrag.set_max_groups(config.max_fragment_groups);
    }

    /// 清理过期数据
    pub async fn cleanup(&self) {
        debug!("开始清理过期数据");
        
        // 清理分片重组器
        let mut defrag = self.defragmenter.write().await;
        defrag.clear();
        
        debug!("清理完成");
    }

    /// 获取配置
    pub fn get_config(&self) -> &ProcessorConfig {
        &self.config
    }
}

/// 批量处理统计信息
#[derive(Debug, Default)]
pub struct BatchProcessStats {
    pub total_packets: usize,
    pub successful_packets: usize,
    pub partial_packets: usize,
    pub failed_packets: usize,
    pub processing_time: Duration,
}

impl BatchProcessStats {
    pub fn throughput(&self) -> f64 {
        self.total_packets as f64 / self.processing_time.as_secs_f64()
    }
    
    pub fn success_rate(&self) -> f64 {
        if self.total_packets == 0 {
            return 0.0;
        }
        self.successful_packets as f64 / self.total_packets as f64
    }
}

fn decoded_to_safepacket(decoded: &DecodedPacket) -> SafePacket {
    let mut data = BytesMut::new();
    // 添加以太网头部
    data.extend_from_slice(&[0u8; 12]); // MAC 地址
    data.extend_from_slice(&[0x08, 0x00]); // 以太网类型 = IPv4
    
    let payload_len = match &decoded.protocol {
        TransportProtocol::TCP { payload, .. } => payload.len(),
        TransportProtocol::UDP { payload, .. } => payload.len(),
        _ => 0,
    };
    
    let total_length = if decoded.ip_header.fragment_offset == 0 {
        20 + 20 + payload_len  // IP头部(20) + TCP头部(20) + payload
    } else {
        20 + payload_len       // IP头部(20) + payload，后续分片不包含TCP头部
    };
    
    // 构建IP头部
    let mut ip_header = Vec::with_capacity(20);
    let version_ihl = (decoded.ip_header.version << 4) | decoded.ip_header.ihl;
    ip_header.push(version_ihl); // 版本(4) + IHL(5)
    ip_header.push(decoded.ip_header.tos); // TOS
    ip_header.extend_from_slice(&(total_length as u16).to_be_bytes());
    ip_header.extend_from_slice(&decoded.ip_header.identification.to_be_bytes());
    
    // 设置flags和fragment_offset
    let offset = decoded.ip_header.fragment_offset; // 直接使用，不需要 /8 转换
    // MF 标志位是第1位 (0x1)，对应网络字节序的 0x2000
    let mut flags_and_offset = offset & 0x1FFF; // 先设置偏移量
    if decoded.ip_header.more_fragments {
        flags_and_offset |= 0x2000; // 设置 MF 标志位，对应网络字节序的 0x1
    }
    if (decoded.ip_header.flags & 0x2) != 0 {
        flags_and_offset |= 0x4000; // 设置 DF 标志位，对应网络字节序的 0x2
    }
    ip_header.extend_from_slice(&flags_and_offset.to_be_bytes());
    
    ip_header.push(decoded.ip_header.ttl);
    ip_header.push(decoded.ip_header.protocol);  // 保持原始协议字段
    ip_header.extend_from_slice(&[0x00, 0x00]); // 校验和
    ip_header.extend_from_slice(&decoded.ip_header.source_ip.to_be_bytes());
    ip_header.extend_from_slice(&decoded.ip_header.dest_ip.to_be_bytes());
    
    // 添加TCP/UDP头部和数据
    match &decoded.protocol {
        TransportProtocol::TCP { src_port, dst_port, seq, ack, flags, window, payload } => {
            if decoded.ip_header.fragment_offset == 0 {
                // 只有第一个分片包含TCP头部
                let mut tcp_header = Vec::with_capacity(20);
                tcp_header.extend_from_slice(&src_port.to_be_bytes());
                tcp_header.extend_from_slice(&dst_port.to_be_bytes());
                tcp_header.extend_from_slice(&seq.to_be_bytes());
                tcp_header.extend_from_slice(&ack.to_be_bytes());
                tcp_header.push(0x50); // 数据偏移
                tcp_header.push(*flags);
                tcp_header.extend_from_slice(&window.to_be_bytes());
                tcp_header.extend_from_slice(&[0x00, 0x00]); // 校验和
                tcp_header.extend_from_slice(&[0x00, 0x00]); // 紧急指针
                data.extend_from_slice(&ip_header);
                data.extend_from_slice(&tcp_header);
            } else {
                data.extend_from_slice(&ip_header);
            }
            data.extend_from_slice(payload);
        }
        TransportProtocol::UDP { src_port, dst_port, payload } => {
            if decoded.ip_header.fragment_offset == 0 {
                // 只有第一个分片包含UDP头部
                let mut udp_header = Vec::with_capacity(8);
                udp_header.extend_from_slice(&src_port.to_be_bytes());
                udp_header.extend_from_slice(&dst_port.to_be_bytes());
                let udp_length = (8 + payload.len()) as u16;
                udp_header.extend_from_slice(&udp_length.to_be_bytes());
                udp_header.extend_from_slice(&[0x00, 0x00]); // 校验和
                data.extend_from_slice(&ip_header);
                data.extend_from_slice(&udp_header);
            } else {
                data.extend_from_slice(&ip_header);
            }
            data.extend_from_slice(payload);
        }
    }
    
    SafePacket::new(data, 0)
}

// 为TransportProtocol添加获取payload的辅助方法
impl TransportProtocol {
    pub fn get_payload(&self) -> &BytesMut {
        match self {
            TransportProtocol::TCP { payload, .. } => payload,
            _ => panic!("不支持的协议类型"),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use super::*;
    use crate::ShardConfig;
    use crate::decode::{DecodedPacket, TransportProtocol, IpHeader};
    use crate::util::log::init_logger;
    use log::{info, debug, error, warn};
    use std::time::Instant;

    fn create_test_packet(offset: u16, more_fragments: bool, payload: &[u8]) -> DecodedPacket {
        DecodedPacket {
            timestamp: 0,
            ip_header: IpHeader {
                version: 4,
                ihl: 5,
                tos: 0,
                total_length: (20 + payload.len()) as u16,
                identification: 1234,
                flags: if more_fragments { 0x1 } else { 0x0 },
                more_fragments,
                fragment_offset: offset,
                ttl: 64,
                protocol: 6,  // TCP
                header_checksum: 0,
                source_ip: u32::from_be_bytes([192,168,1,1]),
                dest_ip: u32::from_be_bytes([192,168,1,2])
            },
            protocol: TransportProtocol::TCP {
                src_port: 1234,
                dst_port: 80,
                seq: 1,
                ack: 0,
                flags: 0x18,  // PSH | ACK
                window: 8192,
                payload: BytesMut::from(payload)
            },
            payload: payload.to_vec()
        }
    }

    fn create_test_tcp_packet() -> SafePacket{
        SafePacket::new(BytesMut::from(&[
            // 以太网头部 (14字节)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 目标MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 源MAC
            0x08, 0x00,                         // 类型 (IPv4)
            // IP header (20字节)
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, // Protocol = 6 (TCP)
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            // TCP header (20字节)
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ][..]), 0)
    }

    fn create_test_ip_fragments() -> (SafePacket, SafePacket) {
        // frag1: offset=0, MF=1, payload=8字节
        let mut data1 = BytesMut::with_capacity(14 + 20 + 20 + 8);
        data1.extend_from_slice(&[
            // 以太网头部 (14字节)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 目标MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 源MAC
            0x08, 0x00,                         // 类型 (IPv4)
            // IP头部 20字节
            0x45, 0x00, 0x00, 0x28, // 版本+IHL, TOS, 总长度(40)
            0x00, 0x01, 0x20, 0x00, // 标识, Flags=0x20(MF=1), Offset=0
            0x40, 0x06, 0x00, 0x00, // TTL, 协议=6, 校验和
            0x7f, 0x00, 0x00, 0x01, // 源IP
            0x7f, 0x00, 0x00, 0x01, // 目标IP
            // TCP头部 20字节
            0x00, 0x50, 0x00, 0x50, // 源端口, 目标端口
            0x00, 0x00, 0x00, 0x00, // 序列号
            0x00, 0x00, 0x00, 0x00, // 确认号
            0x50, 0x02, 0x00, 0x00, // 数据偏移, 标志, 窗口
            0x00, 0x00, 0x00, 0x00, // 校验和, 紧急指针
            // 数据 8字节
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        ]);
        let frag1 = SafePacket::new(data1, 0);
        // frag2: offset=1, MF=0, payload=4字节
        let mut data2 = BytesMut::with_capacity(14 + 20 + 20 + 4);
        data2.extend_from_slice(&[
            // 以太网头部 (14字节)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 目标MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 源MAC
            0x08, 0x00,                         // 类型 (IPv4)
            // IP头部 20字节
            0x45, 0x00, 0x00, 0x24, // 版本+IHL, TOS, 总长度(36)
            0x00, 0x01, 0x00, 0x01,  // 标识, Flags=0, Offset=1 (8字节)
            0x40, 0x06, 0x00, 0x00, // TTL, 协议=6, 校验和
            0x7f, 0x00, 0x00, 0x01, // 源IP
            0x7f, 0x00, 0x00, 0x01, // 目标IP
            // TCP头部 20字节
            0x00, 0x50, 0x00, 0x50, // 源端口, 目标端口
            0x00, 0x00, 0x00, 0x00, // 序列号
            0x00, 0x00, 0x00, 0x00, // 确认号
            0x50, 0x02, 0x00, 0x00, // 数据偏移, 标志, 窗口
            0x00, 0x00, 0x00, 0x00, // 校验和, 紧急指针
            // 数据 4字节
            0x09, 0x0a, 0x0b, 0x0c
        ]);
        let frag2 = SafePacket::new(data2, 0);
        (frag1, frag2)
    }

    fn create_test_ip_fragments_three_parts() -> (SafePacket, SafePacket, SafePacket) {
        let mut data1 = BytesMut::with_capacity(14 + 20 + 20 + 4);
        data1.resize(14, 0);
        data1.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x20, 0x00,  // flags=0x20 (MF=1)，表示有更多分片
            0x40, 0x06, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x03
        ]);
        let frag1 = SafePacket::new(data1, 0);
        let mut data2 = BytesMut::with_capacity(14 + 20 + 20 + 4);
        data2.resize(14, 0);
        data2.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x20, 0x08,  // flags=0x20 (MF=1)，表示有更多分片，offset=8
            0x40, 0x06, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x08, 0x09, 0x0a, 0x0b
        ]);
        let frag2 = SafePacket::new(data2, 0);
        let mut data3 = BytesMut::with_capacity(14 + 20 + 20 + 4);
        data3.resize(14, 0);
        data3.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x00, 0x10,  // flags=0x00 (MF=0)，表示最后一个分片，offset=16
            0x40, 0x06, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x00, 0x50, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x10, 0x11, 0x12, 0x13
        ]);
        let frag3 = SafePacket::new(data3, 0);
        (frag1, frag2, frag3)
    }

    // 辅助函数：将 DecodedPacket 转为 SafePacket
    fn decoded_to_safepacket(decoded: &DecodedPacket) -> SafePacket {
        let mut data = BytesMut::new();
        // 添加以太网头部
        data.extend_from_slice(&[0u8; 12]); // MAC 地址
        data.extend_from_slice(&[0x08, 0x00]); // 以太网类型 = IPv4
        
        let payload_len = match &decoded.protocol {
            TransportProtocol::TCP { payload, .. } => payload.len(),
            TransportProtocol::UDP { payload, .. } => payload.len(),
            _ => 0,
        };
        
        let total_length = if decoded.ip_header.fragment_offset == 0 {
            20 + 20 + payload_len  // IP头部(20) + TCP头部(20) + payload
        } else {
            20 + payload_len       // IP头部(20) + payload，后续分片不包含TCP头部
        };
        
        // 构建IP头部
        let mut ip_header = Vec::with_capacity(20);
        let version_ihl = (decoded.ip_header.version << 4) | decoded.ip_header.ihl;
        ip_header.push(version_ihl); // 版本(4) + IHL(5)
        ip_header.push(decoded.ip_header.tos); // TOS
        ip_header.extend_from_slice(&(total_length as u16).to_be_bytes());
        ip_header.extend_from_slice(&decoded.ip_header.identification.to_be_bytes());
        
        // 设置flags和fragment_offset
        let offset = decoded.ip_header.fragment_offset; // 直接使用，不需要 /8 转换
        // MF 标志位是第1位 (0x1)，对应网络字节序的 0x2000
        let mut flags_and_offset = offset & 0x1FFF; // 先设置偏移量
        if decoded.ip_header.more_fragments {
            flags_and_offset |= 0x2000; // 设置 MF 标志位，对应网络字节序的 0x1
        }
        if (decoded.ip_header.flags & 0x2) != 0 {
            flags_and_offset |= 0x4000; // 设置 DF 标志位，对应网络字节序的 0x2
        }
        ip_header.extend_from_slice(&flags_and_offset.to_be_bytes());
        
        ip_header.push(decoded.ip_header.ttl);
        ip_header.push(decoded.ip_header.protocol);  // 保持原始协议字段
        ip_header.extend_from_slice(&[0x00, 0x00]); // 校验和
        ip_header.extend_from_slice(&decoded.ip_header.source_ip.to_be_bytes());
        ip_header.extend_from_slice(&decoded.ip_header.dest_ip.to_be_bytes());
        
        // 添加TCP/UDP头部和数据
        match &decoded.protocol {
            TransportProtocol::TCP { src_port, dst_port, seq, ack, flags, window, payload } => {
                if decoded.ip_header.fragment_offset == 0 {
                    // 只有第一个分片包含TCP头部
                    let mut tcp_header = Vec::with_capacity(20);
                    tcp_header.extend_from_slice(&src_port.to_be_bytes());
                    tcp_header.extend_from_slice(&dst_port.to_be_bytes());
                    tcp_header.extend_from_slice(&seq.to_be_bytes());
                    tcp_header.extend_from_slice(&ack.to_be_bytes());
                    tcp_header.push(0x50); // 数据偏移
                    tcp_header.push(*flags);
                    tcp_header.extend_from_slice(&window.to_be_bytes());
                    tcp_header.extend_from_slice(&[0x00, 0x00]); // 校验和
                    tcp_header.extend_from_slice(&[0x00, 0x00]); // 紧急指针
                    data.extend_from_slice(&ip_header);
                    data.extend_from_slice(&tcp_header);
                } else {
                    data.extend_from_slice(&ip_header);
                }
                data.extend_from_slice(payload);
            }
            TransportProtocol::UDP { src_port, dst_port, payload } => {
                if decoded.ip_header.fragment_offset == 0 {
                    // 只有第一个分片包含UDP头部
                    let mut udp_header = Vec::with_capacity(8);
                    udp_header.extend_from_slice(&src_port.to_be_bytes());
                    udp_header.extend_from_slice(&dst_port.to_be_bytes());
                    let udp_length = (8 + payload.len()) as u16;
                    udp_header.extend_from_slice(&udp_length.to_be_bytes());
                    udp_header.extend_from_slice(&[0x00, 0x00]); // 校验和
                    data.extend_from_slice(&ip_header);
                    data.extend_from_slice(&udp_header);
                } else {
                    data.extend_from_slice(&ip_header);
                }
                data.extend_from_slice(payload);
            }
        }
        
        SafePacket::new(data, 0)
    }

    #[tokio::test]
    async fn test_packet_processing() {
        init_logger();
        log::info!("开始测试 test_packet_processing");
        
        // 设置超时
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                log::debug!("初始化测试环境");
                let config = ShardConfig::default();
                let reassembler = Arc::new(ShardedTcpReassembler::new(config));
                let processor = PacketProcessor::new(reassembler);
                log::debug!("处理器初始化完成");

                // 创建测试包
                log::debug!("创建测试数据包");
                let test_packet = create_test_tcp_packet();
                log::debug!("测试数据包创建完成: data_len={}", test_packet.data.len());
                
                // 处理包
                log::debug!("开始处理数据包");
                let result = processor.process_packet(&test_packet).await;

                match result {
                    Ok(processing_result) => {
                        match processing_result.stage {
                            ProcessingStage::Complete => {
                                if let Some(data) = processing_result.data {
                                    log::info!("数据包处理成功: 重组数据长度={}", data.len());
                                    log::debug!("重组数据内容: {:?}", data);
                                } else {
                                    log::info!("数据包处理完成，但无重组数据");
                                }
                            },
                            ProcessingStage::StreamReassembly => {
                                log::info!("数据包进入TCP流重组阶段");
                            },
                            _ => {
                                log::info!("数据包处理阶段: {:?}", processing_result.stage);
                            }
                        }
                        
                        if let Some(error) = processing_result.error {
                            log::error!("处理过程中出现错误: {}", error);
                        }
                    },
                    Err(e) => {
                        log::error!("数据包处理失败: {:?}", e);
                        panic!("数据包处理失败: {:?}", e);
                    }
                }

                // 尝试关闭工作线程池，设置超时避免死锁
                log::debug!("准备关闭工作线程池");
                if let Ok(worker_pool) = Arc::try_unwrap(processor.worker_pool) {
                    let shutdown_timeout = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        async {
                            let mut worker_pool = worker_pool;
                            worker_pool.shutdown().await;
                        }
                    ).await;
                    
                    match shutdown_timeout {
                        Ok(_) => log::info!("工作线程池正常关闭"),
                        Err(_) => log::warn!("工作线程池关闭超时"),
                    }
                } else {
                    log::warn!("无法获取独占的工作线程池引用");
                }
                
                log::info!("测试处理完成");
            }
        );

        match timeout.await {
            Ok(_) => log::info!("测试成功完成"),
            Err(_) => {
                log::error!("测试超时！");
                panic!("测试执行时间超过5秒");
            }
        }
    }

    #[tokio::test]
    async fn test_fragmented_packet() {
        init_logger();
        log::info!("开始测试 test_fragmented_packet");
        log::debug!("初始化测试环境");
        let config = ShardConfig::default();
        let reassembler = Arc::new(ShardedTcpReassembler::new(config));
        let processor = PacketProcessor::new(reassembler);
        log::debug!("处理器初始化完成");

        // 构造两个分片：第一个8字节，第二个4字节
        let decoded1 = create_test_packet(0, true, b"abcdefgh"); // offset=0, MF=1
        let decoded2 = create_test_packet(1, false, b"ijkl");    // offset=1 (8字节), MF=0

        log::debug!("分片1信息: id={}, offset={}, more_fragments={}, payload_len={}, src_ip={}, dst_ip={}", 
            decoded1.ip_header.identification, 
            decoded1.ip_header.fragment_offset, 
            decoded1.ip_header.more_fragments, 
            decoded1.payload.len(),
            decoded1.ip_header.source_ip,
            decoded1.ip_header.dest_ip);
        
        log::debug!("分片2信息: id={}, offset={}, more_fragments={}, payload_len={}, src_ip={}, dst_ip={}", 
            decoded2.ip_header.identification, 
            decoded2.ip_header.fragment_offset, 
            decoded2.ip_header.more_fragments, 
            decoded2.payload.len(),
            decoded2.ip_header.source_ip,
            decoded2.ip_header.dest_ip);

        let safe_frag1 = decoded_to_safepacket(&decoded1);
        let safe_frag2 = decoded_to_safepacket(&decoded2);

        log::debug!("SafePacket1长度: {}", safe_frag1.data.len());
        log::debug!("SafePacket2长度: {}", safe_frag2.data.len());

        // 处理第一个分片
        log::debug!("开始处理第一个分片");
        let result1 = processor.process_packet(&safe_frag1).await;
        log::debug!("第一个分片处理结果: {:?}", result1);
        assert!(result1.is_ok());
        let result1 = result1.unwrap();
        log::debug!("第一个分片处理阶段: {:?}, 数据: {:?}", result1.stage, result1.data);
        assert_eq!(result1.stage, ProcessingStage::Defragment);
        assert!(result1.data.is_none());

        // 处理第二个分片，应该触发重组
        log::debug!("开始处理第二个分片");
        let result2 = processor.process_packet(&safe_frag2).await;
        log::debug!("第二个分片处理结果: {:?}", result2);
        assert!(result2.is_ok());
        let result2 = result2.unwrap();
        log::debug!("第二个分片处理阶段: {:?}, 数据: {:?}", result2.stage, result2.data);
        assert_eq!(result2.stage, ProcessingStage::Complete);
        assert!(result2.data.is_some());

        if let Some(reassembled_data) = result2.data {
            log::debug!("重组数据: {:?}", reassembled_data);
            assert_eq!(reassembled_data, b"abcdefghijkl");
        } else {
            panic!("重组数据为空");
        }
    }

    #[tokio::test]
    async fn test_ip_fragmentation_scenarios() {
        init_logger();
        log::info!("开始测试 test_ip_fragmentation_scenarios");
        
        log::debug!("初始化测试环境");
        let config = ShardConfig::default();
        let reassembler = Arc::new(ShardedTcpReassembler::new(config));
        let processor = PacketProcessor::new(reassembler);
        log::debug!("处理器初始化完成");

        // 测试三个分片的情况
        log::debug!("创建三个分片的测试数据");
        let (frag1, frag2, frag3) = create_test_ip_fragments_three_parts();
        log::debug!("测试数据创建完成: frag1_len={}, frag2_len={}, frag3_len={}", 
            frag1.data.len(), frag2.data.len(), frag3.data.len());
        
        // 处理第一个分片
        log::debug!("处理第一个分片");
        let result1 = processor.process_packet(&frag1).await;
        match &result1 {
            Ok(processing_result) => {
                match processing_result.stage {
                    ProcessingStage::Defragment => {
                        log::debug!("第一个分片处理完成，等待更多数据");
                    },
                    ProcessingStage::Complete => {
                        if let Some(data) = &processing_result.data {
                            log::warn!("第一个分片意外返回数据: len={}", data.len());
                        }
                    },
                    _ => {
                        log::debug!("第一个分片处理阶段: {:?}", processing_result.stage);
                    }
                }
            },
            Err(e) => log::error!("第一个分片处理失败: {:?}", e),
        }
        assert!(result1.is_ok());
        
        // 处理第二个分片
        log::debug!("处理第二个分片");
        let result2 = processor.process_packet(&frag2).await;
        match &result2 {
            Ok(processing_result) => {
                match processing_result.stage {
                    ProcessingStage::Defragment => {
                        log::debug!("第二个分片处理完成，继续等待");
                    },
                    ProcessingStage::Complete => {
                        if let Some(data) = &processing_result.data {
                            log::warn!("第二个分片意外返回数据: len={}", data.len());
                        }
                    },
                    _ => {
                        log::debug!("第二个分片处理阶段: {:?}", processing_result.stage);
                    }
                }
            },
            Err(e) => log::error!("第二个分片处理失败: {:?}", e),
        }
        assert!(result2.is_ok());
        
        // 处理第三个（最后）分片
        log::debug!("处理第三个分片");
        let result3 = processor.process_packet(&frag3).await;
        match &result3 {
            Ok(processing_result) => {
                match processing_result.stage {
                    ProcessingStage::Complete => {
                        if let Some(data) = &processing_result.data {
                            log::info!("分片重组成功: 数据长度={}", data.len());
                            log::debug!("重组数据内容: {:?}", data);
                        } else {
                            log::warn!("第三个分片处理后未返回数据");
                        }
                    },
                    ProcessingStage::Defragment => {
                        log::warn!("第三个分片处理后仍在分片阶段");
                    },
                    _ => {
                        log::warn!("第三个分片处理阶段: {:?}", processing_result.stage);
                    }
                }
            },
            Err(e) => {
                log::error!("第三个分片处理失败: {:?}", e);
            }
        };
        
        assert!(result3.is_ok());
        log::info!("三片段重组测试完成");
    }

    #[tokio::test]
    async fn test_error_handling() {
        init_logger();
        log::info!("开始测试 test_error_handling");
        
        log::debug!("初始化测试环境");
        let config = ShardConfig::default();
        let reassembler = Arc::new(ShardedTcpReassembler::new(config));
        let processor = PacketProcessor::new(reassembler);
        log::debug!("处理器初始化完成");

        // 测试空指针
        log::debug!("测试空指针情况");
        let null_packet = SafePacket::new(BytesMut::new(), 0);
        let result = processor.process_packet(&null_packet).await;
        match &result {
            Ok(processing_result) => {
                if processing_result.error.is_some() {
                    log::debug!("空数据包处理返回预期错误: {:?}", processing_result.error);
                } else {
                    log::warn!("空数据包处理未返回错误");
                }
            },
            Err(e) => log::debug!("空数据包处理返回错误: {:?}", e),
        }
        assert!(result.is_ok());

        // 测试无效数据包
        log::debug!("测试无效数据包");
        let mut invalid_data = BytesMut::from(&[0u8; 10][..]); // 太短的数据包
        let invalid_packet = SafePacket::new(invalid_data, 0);
        let result = processor.process_packet(&invalid_packet).await;
        match &result {
            Ok(processing_result) => {
                if processing_result.error.is_some() {
                    log::debug!("无效数据包处理返回预期错误: {:?}", processing_result.error);
                } else {
                    log::warn!("无效数据包处理未返回错误");
                }
            },
            Err(e) => log::debug!("无效数据包处理返回错误: {:?}", e),
        }
        assert!(result.is_ok());

        log::info!("错误处理测试完成");
    }
}