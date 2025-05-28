pub mod config;
pub mod error;
pub mod decode;
pub mod defrag;
pub mod stream;
pub mod processor;


// Re-export commonly used types
pub use decode::{DecodedPacket, IpHeader, decode_packet};
pub use processor::PacketProcessor;
pub use defrag::IpDefragmenter;
pub use stream::{ShardedTcpReassembler, ShardConfig};
pub use error::{Result, PacketError, ReassembleError};
pub use tokio::runtime::Runtime;
pub use std::sync::OnceLock;
pub use std::sync::Arc;
use futures::TryFutureExt;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        // 创建多线程运行时
        Runtime::new().expect("Failed to create Tokio runtime")
    })
}

// 全局共享重组器
static REASSEMBLER: OnceLock<Arc<ShardedTcpReassembler>> = OnceLock::new();

fn get_reassembler() -> &'static Arc<ShardedTcpReassembler> {
    REASSEMBLER.get_or_init(|| {
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
    data: *const u8,
    len: usize,
    timestamp: u64,
}

// 添加一个安全的包结构体
#[derive(Clone)]
pub struct SafePacket {
    pub data: Vec<u8>,
    pub timestamp: u64,
}

impl SafePacket {
    pub fn new(data: Vec<u8>, timestamp: u64) -> Self {
        Self { data, timestamp }
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
                data: slice.to_vec(),
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

