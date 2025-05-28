use std::sync::Arc;
use libc::_SC_EQUIV_CLASS_MAX;
use tokio::sync::RwLock;
use super::stream_tcp::TcpReassembler;
use crate::decode::DecodedPacket;
use crate::error::Result;
use std::num::Wrapping;
use std::collections::HashMap;
use tokio::time::{Duration, Instant};
use log::{warn, info};

/// 分片重组器的配置参数
#[derive(Debug, Clone)]
pub struct ShardConfig {
    /// 分片数量
    pub shard_count: usize,
    /// 超时时间(秒)
    pub timeout_secs: u64,
    /// 最大 gap 大小
    pub max_gap: u32,
    /// 每个分片的最大流数量
    pub max_streams_per_shard: usize,
    /// 每个流的最大段数
    pub max_segments: usize,
    /// 重平衡阈值(字节)
    pub rebalance_threshold: usize,
    /// 统计信息清理间隔(秒)
    pub stats_cleanup_interval: u64,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            shard_count: num_cpus::get(),
            timeout_secs: 30,
            max_gap: 1024,
            max_streams_per_shard: 1000,
            max_segments: 100,
            rebalance_threshold: 1_000_000,
            stats_cleanup_interval: 300,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StreamStats {
    pub packet_count: u64,
    pub byte_count: u64,
    pub last_seen: Instant,
    pub gaps_detected: u64,
    pub retransmissions: u64,
    pub out_of_order: u64,
    pub reassambled_errors: u64,
}

impl Default for StreamStats {
    fn default() -> Self {
        Self {
            packet_count: 0,
            byte_count: 0,
            last_seen: Instant::now(),
            gaps_detected: 0,
            retransmissions: 0,
            out_of_order: 0,
            reassambled_errors: 0,
        }
    }
}

pub struct ShardedTcpReassembler {
    shards: Vec<Arc<RwLock<TcpReassembler>>>,
    shard_count: usize,
    stream_stats: Arc<RwLock<HashMap<String, StreamStats>>>,
    rebalance_threshold: Arc<RwLock<usize>>,
    config: ShardConfig,
}

// 添加 Clone trait 实现
impl Clone for ShardedTcpReassembler {
    fn clone(&self) -> Self {
        Self {
            shards: self.shards.clone(),
            shard_count: self.shard_count,
            stream_stats: self.stream_stats.clone(),
            rebalance_threshold: self.rebalance_threshold.clone(),
            config: self.config.clone(),
        }
    }
}

impl ShardedTcpReassembler {
    pub fn new(config: ShardConfig) -> Self {
        let mut shards = Vec::with_capacity(config.shard_count);
        
        for _ in 0..config.shard_count {
            shards.push(Arc::new(RwLock::new(TcpReassembler::new(
                config.timeout_secs,
                config.max_gap,
                config.max_streams_per_shard,
                config.max_segments,
            ))));
        }

        Self {
            shards,
            shard_count: config.shard_count,
            stream_stats: Arc::new(RwLock::new(HashMap::new())),
            rebalance_threshold: Arc::new(RwLock::new(config.rebalance_threshold)),
            config,
        }
    }

    /// 启动后台任务
    pub async fn start_background_tasks(self: Arc<Self>) -> Result<()> {
        // 清理任务
        let cleanup_handle = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = cleanup_handle.cleanup_all().await {
                    warn!("清理任务失败: {}", e);
                }
            }
        });

        // 负载均衡监控任务
        let monitor_handle = self.clone();
        tokio::spawn(async move {
            if let Err(e) = monitor_handle.monitor_load_balance().await {
                warn!("负载均衡监控失败: {}", e);
            }
        });

        Ok(())
    }

    async fn get_smart_shard_index(&self, stream_key: &str, packet: &DecodedPacket) -> usize {
        let mut stats = self.stream_stats.write().await;
        let stream_stat = stats.entry(stream_key.to_string())
            .or_insert_with(StreamStats::default);

        // 更新统计信息
        stream_stat.packet_count += 1;
        stream_stat.byte_count += packet.payload.len() as u64;
        stream_stat.last_seen = Instant::now();

        let seq = match packet.protocol {
            crate::decode::TransportProtocol::Tcp { seq, .. } => seq,
            _ => 0, // 对于非TCP协议，序列号为0
        };

        // 如果流量超过阈值，使用序列号进行二次分片
        let threshold = *self.rebalance_threshold.read().await;
        if stream_stat.byte_count >= threshold as u64 {
            let seq_shard = (seq as usize) % self.shard_count;
            return seq_shard;
        }

        self.get_hash_shard_index(stream_key)
    }

    fn get_hash_shard_index(&self, stream_key: &str) -> usize {
        let mut hash = Wrapping(0u64);
        for byte in stream_key.bytes() {
            hash += Wrapping(byte as u64);
            hash += hash << 10;
            hash ^= hash >> 6;
        }
        hash += hash << 3;
        hash ^= hash >> 11;
        hash += hash << 15;
        
        (hash.0 as usize) % self.shard_count
    }

    pub async fn process_packet(&self, packet: &DecodedPacket) -> Option<Vec<u8>> {
        let stream_key = format!("{}:{}-{}:{}",
            packet.ip_header.src_ip,
            packet.src_port,
            packet.ip_header.dst_ip,
            packet.dst_port
        );

        let shard_index = self.get_smart_shard_index(&stream_key, packet).await;
        let shard = &self.shards[shard_index];

        let mut reassembler = shard.write().await;
        reassembler.process_packet(packet)
    }

    pub async fn process_packets(&self, packets: Vec<DecodedPacket>) -> Vec<Option<Vec<u8>>> {
        let mut futures = Vec::with_capacity(packets.len());

        for packet in packets {
            let packet_owned = packet.clone();
            let self_clone = self.clone();
            let future = async move {
                self_clone.process_packet(&packet_owned).await
            };
            futures.push(future);
        }

        futures::future::join_all(futures).await
    }

    pub async fn cleanup_all(&self) -> Result<()> {
        let now = Instant::now();
        let futures: Vec<_> = self.shards.iter()
            .map(|shard| {
                let shard = shard.clone();
                async move {
                    let mut reassembler = shard.write().await;
                    reassembler.cleanup_expired(now);
                }
            })
            .collect();

        futures::future::join_all(futures).await;
        Ok(())
    }

    pub async fn cleanup_stats(&self) {
        let mut stats = self.stream_stats.write().await;
        let now = Instant::now();
        stats.retain(|_, stat| {
            now.duration_since(stat.last_seen) < Duration::from_secs(self.config.stats_cleanup_interval)
        });
    }

    pub async fn get_shard_stats(&self) -> Vec<usize> {
        let mut stats = Vec::with_capacity(self.shard_count);
        for shard in &self.shards {
            let reassembler = shard.read().await;
            stats.push(reassembler.get_stream_count());
        }
        stats
    }

    pub async fn monitor_load_balance(&self) -> Result<()> {
        let mut interval: tokio::time::Interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            
            let stats = self.get_shard_stats().await;
            let total_streams: usize = stats.iter().sum();
            let avg_streams = total_streams / self.shard_count;
            
            let variance: f64 = stats.iter()
                .map(|&count| (count as f64 - avg_streams as f64).powi(2))
                .sum::<f64>() / self.shard_count as f64;
            let std_dev = variance.sqrt();

            if std_dev > (avg_streams as f64 * 0.5) {
                let mut threshold = self.rebalance_threshold.write().await;
                *threshold = (*threshold as f64 * 0.8) as usize;
            }
        }
    }

    pub async fn get_stream_stats(&self, stream_key: &str) -> Option<StreamStats> {
        let stats = self.stream_stats.read().await;
        stats.get(stream_key).cloned()
    }

    pub async fn get_all_stats(&self) -> HashMap<String, StreamStats> {
        let stats = self.stream_stats.read().await;
        stats.clone()
    }

    pub async fn reset_stats(&self) {
        let mut stats = self.stream_stats.write().await;
        stats.clear();
    }

    pub async fn get_health_status(&self) -> Result<bool> {
        let stats = self.get_shard_stats().await;
        let total_streams: usize = stats.iter().sum();
        let avg_streams = total_streams / self.shard_count;
        
        let variance: f64 = stats.iter()
            .map(|&count| (count as f64 - avg_streams as f64).powi(2))
            .sum::<f64>() / self.shard_count as f64;
        let std_dev = variance.sqrt();

        Ok(std_dev <= (avg_streams as f64 * 0.5))
    }

    pub async fn shutdown(&self) -> Result<()> {
        info!("开始关闭分片重组器...");
        
        for shard in &self.shards {
            let reassembler = shard.read().await;
        }

        self.save_stats().await?;

        info!("分片重组器已关闭");
        Ok(())
    }

    async fn save_stats(&self) -> Result<()> {
        Ok(())
    }

    // 使用示例:
    pub async fn run(config: ShardConfig) -> Result<()> {
        let reassembler = Arc::new(ShardedTcpReassembler::new(config));
        
        // 启动后台任务
        reassembler.start_background_tasks().await?;
        
        // 主处理循环
        loop {
            // 处理数据包...
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    use crate::decode::{DecodedPacket, IpHeader, TransportProtocol};

    fn dummy_packet() -> DecodedPacket {
        DecodedPacket {
            ip_header: IpHeader {
                src_ip: "127.0.0.1".parse().unwrap(),
                dst_ip: "127.0.0.1".parse().unwrap(),
                protocol: 6,
                version: 4,
                ihl: 5,
                total_length: 40,
                identification: 54321,
                flags: 0,
                fragment_offset: 0,
                ttl: 64,
                checksum: 0,
            },
            src_port: 1234,
            dst_port: 5678,
            protocol: TransportProtocol::Tcp { seq: 0, ack: 0 , 
                flags: 0, window: 0},
            payload: vec![],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        }
    }

    #[tokio::test]
    async fn test_shard_distribution() {
        let config = ShardConfig {
            shard_count: 4,
            ..Default::default()
        };
        
        let reassembler = ShardedTcpReassembler::new(config);
        
        // 测试流分布
        let mut packet_counts = vec![0; 4];
        for i in 0..1000 {
            let stream_key = format!("test-stream-{}", i);
            let shard_idx = reassembler.get_smart_shard_index(&stream_key, &dummy_packet()).await;
            packet_counts[shard_idx] += 1;
        }
        
        // 检查分布是否均匀
        let avg = packet_counts.iter().sum::<usize>() / packet_counts.len();
        for count in packet_counts {
            assert!((count as i32 - avg as i32).abs() < 100);
        }
    }

    fn create_large_test_packet() -> DecodedPacket {
        let mut packet = dummy_packet();
        packet.payload = vec![0; 1024]; // 1KB payload
        packet
    }

    #[tokio::test]
    async fn test_load_balancing() {
        let config = ShardConfig::default();
        let reassembler = Arc::new(ShardedTcpReassembler::new(config));
        
        // 启动后台任务
        reassembler.clone().start_background_tasks().await.unwrap();
        
        // 模拟负载不均衡
        for _ in 0..1000 {
            let mut packet = create_large_test_packet();
            packet.src_port = 12345;
            packet.dst_port = 54321;
            reassembler.process_packet(&packet).await;
        }
        
        // 等待负载均衡
        sleep(Duration::from_secs(2)).await;
        
        // 检查分片是否已重新平衡
        let stats = reassembler.get_shard_stats().await;
        let max_diff = stats.iter().max().unwrap() - stats.iter().min().unwrap();
        assert!(max_diff < 100);
    }
}