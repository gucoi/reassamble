#[derive(Default, Debug)]
pub struct DecodeStats {
    pub ethernet_packets: usize,
    pub ipv4_packets: usize,
    pub ipv6_packets: usize,
    pub tcp_packets: usize,
    pub udp_packets: usize,
    pub errors: usize,
    // 可扩展更多统计
}

#[derive(Debug)]
pub struct DecodeContext {
    pub stats: DecodeStats,
    pub errors: Vec<String>,
    // 可扩展更多上下文信息
}

impl DecodeContext {
    pub fn new() -> Self {
        Self {
            stats: DecodeStats::default(),
            errors: Vec::new(),
        }
    }
    pub fn record_error(&mut self, err: &str) {
        self.stats.errors += 1;
        self.errors.push(err.to_string());
    }
} 