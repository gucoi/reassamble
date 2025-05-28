use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Config {
    pub defrag_timeout: u64,      // IP分片超时时间（秒）
    pub stream_timeout: u64,      // 流超时时间（秒）
    pub max_fragments: usize,     // 每个 IP 分片组的最大分片数
    pub max_streams: usize,       // 最大并发流数量
}

impl Default for Config {
    fn default() -> Self {
        Self {
            defrag_timeout: 30,
            stream_timeout: 300,
            max_fragments: 1024,
            max_streams: 10000,
        }
    }
}
