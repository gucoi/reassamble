pub mod config;
pub mod error;
pub mod decode;
pub mod defrag;
pub mod stream;
pub mod processor;
pub mod ffi;
pub mod memory;


// Re-export commonly used types
pub use decode::{DecodedPacket, IpHeader, decode_packet};
pub use processor::PacketProcessor;
pub use defrag::IpDefragmenter;
pub use stream::{ShardedTcpReassembler, ShardConfig};
pub use error::{Result, PacketError, ReassembleError};
pub use memory::{MemoryPool, MemoryBlock, MemoryPoolConfig, init_global_pool, get_global_pool};
pub use tokio::runtime::Runtime;
pub use std::sync::OnceLock;
pub use std::sync::Arc;
use futures::TryFutureExt;
use bytes::{Bytes, BytesMut, BufMut};
use std::time::{Duration, Instant};
use log::{info, warn, error};
use thiserror::Error;

// 重新导出常用类型
pub use ffi::types::{CapturePacket, ReassemblePacket};
pub use ffi::capture::{capture_init, capture_start, capture_stop};
pub use ffi::reassemble::process_reassemble_packet;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        // 创建多线程运行时
        Runtime::new().expect("Failed to create Tokio runtime")
    })
}

// 初始化内存池
pub fn init_memory_pool() {
    let config = MemoryPoolConfig {
        min_block_size: 1024,
        max_block_size: 1024 * 1024, // 1MB
        initial_pool_size: 1000,
        max_pool_size: 10000,
    };
    init_global_pool(Some(config));
}

// 全局共享重组器
static REASSEMBLER: OnceLock<Arc<ShardedTcpReassembler>> = OnceLock::new();

fn get_reassembler() -> &'static Arc<ShardedTcpReassembler> {
    REASSEMBLER.get_or_init(|| {
        // 确保内存池已初始化
        init_memory_pool();
        
        let config = ShardConfig::default();
        let reassembler = Arc::new(ShardedTcpReassembler::new(config));
        
        // 启动后台任务
        let rt = get_runtime();
        rt.block_on(async {
            reassembler.clone().start_background_tasks().await.expect("Failed to start background tasks");
        });
        
        reassembler
    })
}

static PROCESSOR: OnceLock<Arc<PacketProcessor>> = OnceLock::new();

fn get_processor() -> &'static Arc<PacketProcessor> {
    PROCESSOR.get_or_init(|| {
        let reassembler = get_reassembler().clone();
        Arc::new(PacketProcessor::new(reassembler))
    })
}

#[repr(C)]
pub struct Packet {
    pub data: *const u8,
    pub len: usize,
    pub timestamp: u64,
}

// 添加一个安全的包结构体
#[derive(Debug, Clone)]
pub struct SafePacket {
    pub data: BytesMut,
    pub timestamp: u64,
}

impl SafePacket {
    pub fn new(data: BytesMut, timestamp: u64) -> Self {
        Self {
            data,
            timestamp,
        }
    }

    pub fn from_bytes(data: &[u8], timestamp: u64) -> Self {
        Self {
            data: BytesMut::from(data),
            timestamp,
        }
    }
}

#[no_mangle]
pub extern "C" fn process_packet(packet: *const Packet) -> Result<()> {
    if packet.is_null() || unsafe { (*packet).data.is_null() } {
        return Err(ReassembleError::PacketError(PacketError::NullPointer));
    }

    let processor = get_processor();
    let rt = get_runtime();
    
    rt.block_on(async {
        // 先复制数据到安全的 Vec 中
        let packet_data = unsafe { 
            let p = &*packet;
            let slice = std::slice::from_raw_parts(p.data, p.len);
            SafePacket {
                data: BytesMut::from(slice),
                timestamp: p.timestamp,
            }
        };
        
        // 在工作线程中处理
        let result = processor.process_packet(&packet_data).await?;

        if let Some(data) = result {
            println!("Reassembled {} bytes", data.len());
        }
        
        Ok(())
    })
}

