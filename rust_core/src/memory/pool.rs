use super::MemoryBlock;
use std::sync::atomic::{AtomicUsize, Ordering};
use crate::error::{Result, ReassembleError};
use log;

#[derive(Debug, Clone)]
pub struct MemoryPoolConfig {
    pub min_block_size: usize,
    pub max_block_size: usize,
    pub initial_pool_size: usize,
    pub max_pool_size: usize,
}

impl Default for MemoryPoolConfig {
    fn default() -> Self {
        Self {
            min_block_size: 64,
            max_block_size: 65536,
            initial_pool_size: 1000,
            max_pool_size: 10000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryPoolStats {
    pub total_allocated: usize,
    pub total_freed: usize,
    pub allocation_count: usize,
    pub free_count: usize,
    pub current_blocks: usize,
}

/// 内存池实现
pub struct MemoryPool {
    config: MemoryPoolConfig,
    blocks: Vec<MemoryBlock>,
    total_allocated: AtomicUsize,
    total_freed: AtomicUsize,
    allocation_count: AtomicUsize,
    free_count: AtomicUsize,
}

impl MemoryPool {
    pub fn new(config: MemoryPoolConfig) -> Self {
        log::debug!("创建新的内存池: min_block_size={}, max_block_size={}, initial_pool_size={}, max_pool_size={}", 
            config.min_block_size, config.max_block_size, config.initial_pool_size, config.max_pool_size);
            
        let mut pool = Self {
            blocks: Vec::with_capacity(config.initial_pool_size),
            config: config.clone(),  // 克隆配置以避免移动
            total_allocated: AtomicUsize::new(0),
            total_freed: AtomicUsize::new(0),
            allocation_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
        };

        // 预分配初始块
        for _ in 0..config.initial_pool_size {
            let block = MemoryBlock::new(config.min_block_size);
            pool.blocks.push(block);
        }

        log::debug!("内存池初始化完成: 预分配块数={}", pool.blocks.len());
        pool
    }

    pub fn allocate(&mut self, size: usize) -> Result<MemoryBlock> {
        log::debug!("请求分配内存: size={}, 当前可用块数={}", size, self.blocks.len());
        
        // 检查大小是否在允许范围内
        if size < self.config.min_block_size || size > self.config.max_block_size {
            log::error!("请求的内存大小超出范围: size={}, min={}, max={}", 
                size, self.config.min_block_size, self.config.max_block_size);
            return Err(ReassembleError::DecodeError(format!(
                "Requested size {} is outside allowed range [{}, {}]",
                size, self.config.min_block_size, self.config.max_block_size
            )));
        }

        // 尝试从池中获取块
        if let Some(mut block) = self.blocks.pop() {
            let block_size = block.size();  // 在移动之前获取大小
            block.mark_used();
            self.allocation_count.fetch_add(1, Ordering::SeqCst);
            self.total_allocated.fetch_add(block_size, Ordering::SeqCst);
            return Ok(block);
        }

        // 如果池为空，创建新块
        log::debug!("池为空，创建新内存块: size={}", size);
        let mut block = MemoryBlock::new(size);
        let block_size = block.size();  // 在移动之前获取大小
        block.mark_used();
        self.allocation_count.fetch_add(1, Ordering::SeqCst);
        self.total_allocated.fetch_add(block_size, Ordering::SeqCst);
        Ok(block)
    }

    pub fn free(&mut self, mut block: MemoryBlock) {
        let block_size = block.size();  // 在移动之前获取大小
        log::debug!("释放内存块: size={}, 当前池大小={}", block_size, self.blocks.len());
        
        // 检查池是否已满
        if self.blocks.len() >= self.config.max_pool_size {
            log::debug!("内存池已满，直接释放块");
            block.mark_free();
            self.free_count.fetch_add(1, Ordering::SeqCst);
            self.total_freed.fetch_add(block_size, Ordering::SeqCst);
            return;
        }

        // 重置块并添加到池中
        block.mark_free();
        self.blocks.push(block);
        self.free_count.fetch_add(1, Ordering::SeqCst);
        self.total_freed.fetch_add(block_size, Ordering::SeqCst);
        
        log::debug!("内存块已回收到池中: 当前池大小={}", self.blocks.len());
    }

    pub fn stats(&self) -> MemoryPoolStats {
        let allocated = self.total_allocated.load(Ordering::SeqCst);
        let freed = self.total_freed.load(Ordering::SeqCst);
        let alloc_count = self.allocation_count.load(Ordering::SeqCst);
        let free_count = self.free_count.load(Ordering::SeqCst);
        
        log::debug!("内存池统计: allocated={}, freed={}, alloc_count={}, free_count={}, current_blocks={}", 
            allocated, freed, alloc_count, free_count, self.blocks.len());
            
        MemoryPoolStats {
            total_allocated: allocated,
            total_freed: freed,
            allocation_count: alloc_count,
            free_count,
            current_blocks: self.blocks.len(),
        }
    }
}

impl Default for MemoryPool {
    fn default() -> Self {
        Self::new(MemoryPoolConfig::default())
    }
} 