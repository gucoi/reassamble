use super::MemoryBlock;
use std::sync::Arc;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use crossbeam::queue::SegQueue;
use num_cpus;
use bytes::{Bytes, BytesMut, BufMut};

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

/// 内存池实现
pub struct MemoryPool {
    config: MemoryPoolConfig,
    blocks: Vec<MemoryBlock>,
}

impl MemoryPool {
    pub fn new(config: MemoryPoolConfig) -> Self {
        let mut blocks = Vec::with_capacity(config.initial_pool_size);
        for _ in 0..config.initial_pool_size {
            blocks.push(MemoryBlock::new(config.min_block_size));
        }
        Self { config, blocks }
    }

    pub fn acquire(&mut self, size: usize) -> Option<MemoryBlock> {
        if size > self.config.max_block_size {
            return None;
        }

        // 查找合适大小的块
        if let Some(index) = self.blocks.iter().position(|block| {
            !block.is_used() && block.size() >= size
        }) {
            let mut block = self.blocks.remove(index);
            block.mark_used();
            Some(block)
        } else {
            // 如果没有合适的块，创建新的
            if self.blocks.len() < self.config.max_pool_size {
                let mut block = MemoryBlock::new(size);
                block.mark_used();
                Some(block)
            } else {
                None
            }
        }
    }

    pub fn release(&mut self, mut block: MemoryBlock) {
        if self.blocks.len() < self.config.max_pool_size {
            block.mark_free();
            self.blocks.push(block);
        }
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    pub fn available_blocks(&self) -> usize {
        self.blocks.len()
    }
}

impl Default for MemoryPool {
    fn default() -> Self {
        Self::new(MemoryPoolConfig::default())
    }
} 