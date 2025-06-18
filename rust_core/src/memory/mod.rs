use std::sync::Arc;
use parking_lot::Mutex;
use std::collections::HashMap;

mod block;
mod pool;

pub use block::MemoryBlock;
pub use pool::MemoryPool;
pub use pool::MemoryPoolConfig;

lazy_static::lazy_static! {
    static ref GLOBAL_POOL: Arc<Mutex<HashMap<usize, Arc<Mutex<MemoryPool>>>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub fn init_global_pool(config: Option<MemoryPoolConfig>) {
    let config = config.unwrap_or_else(|| MemoryPoolConfig {
        min_block_size: 1024,
        max_block_size: 1024 * 1024,
        initial_pool_size: 100,
        max_pool_size: 1000,
    });

    let mut pools = GLOBAL_POOL.lock();
    pools.insert(config.min_block_size, Arc::new(Mutex::new(MemoryPool::new(config.clone()))));
}

pub fn get_global_pool() -> Arc<Mutex<HashMap<usize, Arc<Mutex<MemoryPool>>>>> {
    GLOBAL_POOL.clone()
}

pub fn get_pool(size: usize) -> Option<Arc<Mutex<MemoryPool>>> {
    let pools = GLOBAL_POOL.lock();
    pools.get(&size).cloned()
} 