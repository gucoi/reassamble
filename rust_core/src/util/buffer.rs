pub struct BufferPool {
    pool: Arc<DashMap<usize, Vec<Vec<u8>>>>,
    max_size: usize,
}

impl BufferPool {
    pub fn new(max_size: usize) -> Self {
        Self {
            pool: Arc::new(DashMap::new()),
            max_size,
        }
    }
    
    pub async fn acquire(&self) -> Vec<u8> {
        // 从池中获取或创建新的缓冲区
        self.pool.entry(1024)
            .or_insert_with(|| Vec::with_capacity(32))
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(1024))
    }
    
    pub async fn release(&self, mut buffer: Vec<u8>) {
        if self.pool.len() < self.max_size {
            buffer.clear();
            self.pool.entry(buffer.capacity())
                .or_insert_with(Vec::new)
                .push(buffer);
        }
    }
}