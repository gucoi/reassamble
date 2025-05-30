use rust_core::{
    stream::{ShardedTcpReassembler, ShardConfig},
    processor::{PacketProcessor, BatchPacket},
    ffi::capture::{capture_init, capture_start, capture_stop, capture_cleanup},
    ffi::types::{CaptureConfig, CaptureBackendType, CapturePacket},
    SafePacket,
};
use std::sync::Arc;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::time::{sleep, Duration};
use std::ffi::{CString, CStr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::os::raw::{c_char, c_void};
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use log::{info, error};
use std::collections::VecDeque;
use bytes::BytesMut;
use libc;

static PROCESSOR_CELL: OnceCell<Arc<PacketProcessor>> = OnceCell::new();
static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static PACKET_BUFFER: OnceCell<Mutex<VecDeque<SafePacket>>> = OnceCell::new();
const BATCH_SIZE: usize = 1000;  // 每批处理的包数量

// 初始化包缓冲区
fn init_packet_buffer() {
    PACKET_BUFFER.set(Mutex::new(VecDeque::with_capacity(BATCH_SIZE))).ok();
}

// 创建测试用的 TCP 数据包
fn create_test_tcp_packet(
    seq: u32,
    payload: &[u8],
    flags: u8,
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
) -> SafePacket {
    let mut data = BytesMut::with_capacity(54 + payload.len());
    data.resize(54 + payload.len(), 0);
    
    // 填充以太网头部 (14字节)
    data[0..6].fill(0x00);  // 目标MAC
    data[6..12].fill(0x00); // 源MAC
    data[12..14].fill(0x08); // 类型 (IPv4)
    
    // 填充IP头部 (20字节)
    data[14] = 0x45;  // 版本(4) + IHL(5)
    data[15] = 0x00;  // 服务类型
    let total_length: u16 = (20 + 20 + payload.len()) as u16; // IP头部(20) + TCP头部(20) + payload
    let total_length_bytes = total_length.to_be_bytes();
    data[16..18].copy_from_slice(&total_length_bytes);
    data[18..20].fill(0x00); // 标识
    data[20] = 0x40;  // 标志 + 片偏移
    data[21] = 0x00;  // 片偏移
    data[22] = 0x40;  // TTL
    data[23] = 0x06;  // 协议 (TCP)
    data[24..26].fill(0x00); // 校验和
    
    // 源IP
    let src_ip = IpAddr::from_str(src_ip).unwrap();
    match src_ip {
        IpAddr::V4(ip) => data[26..30].copy_from_slice(&ip.octets()),
        _ => panic!("只支持 IPv4"),
    }
    
    // 目标IP
    let dst_ip = IpAddr::from_str(dst_ip).unwrap();
    match dst_ip {
        IpAddr::V4(ip) => data[30..34].copy_from_slice(&ip.octets()),
        _ => panic!("只支持 IPv4"),
    }
    
    // 填充TCP头部 (20字节)
    data[34..36].copy_from_slice(&src_port.to_be_bytes());
    data[36..38].copy_from_slice(&dst_port.to_be_bytes());
    data[38..42].copy_from_slice(&seq.to_be_bytes());
    data[42..46].fill(0x00); // 确认号
    data[46] = 0x50;  // 数据偏移
    data[47] = flags; // 标志
    data[48..50].fill(0x20); // 窗口大小
    data[50..52].fill(0x00); // 校验和
    data[52..54].fill(0x00); // 紧急指针
    
    // 填充payload
    data[54..].copy_from_slice(payload);
    
    SafePacket::new(data, 0)
}

// 创建分片测试包
fn create_fragmented_packets(
    payload: &[u8],
    fragment_size: usize,
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
) -> Vec<SafePacket> {
    let mut packets = Vec::new();
    let mut offset = 0;
    let mut seq: u32 = 1;
    
    while offset < payload.len() {
        let end = std::cmp::min(offset + fragment_size, payload.len());
        let fragment = &payload[offset..end];
        let is_last = end == payload.len();
        
        let mut data = BytesMut::with_capacity(54 + fragment.len());
        data.resize(54 + fragment.len(), 0);
        
        // 填充以太网头部
        data[0..6].fill(0x00);
        data[6..12].fill(0x00);
        data[12..14].fill(0x08);
        
        // 填充IP头部
        data[14] = 0x45;
        data[15] = 0x00;
        let total_length = ((54 + fragment.len()) as u16).to_be_bytes();
        data[16..18].copy_from_slice(&total_length);
        data[18..20].fill(0x00);
        
        // 设置分片标志
        data[20] = if is_last { 0x00 } else { 0x20 };
        let fragment_offset = (offset / 8) as u16;
        data[21] = (fragment_offset & 0xFF) as u8;
        data[20] |= ((fragment_offset >> 8) & 0x1F) as u8;
        
        data[22] = 0x40;
        data[23] = 0x06;
        data[24..26].fill(0x00);
        
        // 源IP
        let src_ip = IpAddr::from_str(src_ip).unwrap();
        match src_ip {
            IpAddr::V4(ip) => data[26..30].copy_from_slice(&ip.octets()),
            _ => panic!("只支持 IPv4"),
        }
        
        // 目标IP
        let dst_ip = IpAddr::from_str(dst_ip).unwrap();
        match dst_ip {
            IpAddr::V4(ip) => data[30..34].copy_from_slice(&ip.octets()),
            _ => panic!("只支持 IPv4"),
        }
        
        // 填充TCP头部
        data[34..36].copy_from_slice(&src_port.to_be_bytes());
        data[36..38].copy_from_slice(&dst_port.to_be_bytes());
        data[38..42].copy_from_slice(&seq.to_be_bytes());
        data[42..46].fill(0x00);
        data[46] = 0x50;
        data[47] = if is_last { 0x18 } else { 0x08 }; // PSH | ACK 或 ACK
        data[48..50].fill(0x20);
        data[50..52].fill(0x00);
        data[52..54].fill(0x00);
        
        // 填充payload
        data[54..].copy_from_slice(fragment);
        
        packets.push(SafePacket::new(data, 0));
        
        offset = end;
        seq += fragment.len() as u32;
    }
    
    packets
}

// 测试回调函数
extern "C" fn test_packet_callback(packet: *const CapturePacket, user_data: *mut c_void) -> bool {
    if user_data.is_null() {
        error!("[Rust] test_packet_callback: user_data is null");
        return false;
    }
    let running = unsafe { &*(user_data as *const AtomicBool) };
    let flag = running.load(Ordering::Relaxed);

    // 处理捕获到的数据包
    if !packet.is_null() {
        let packet = unsafe { &*packet };
        let data = unsafe { std::slice::from_raw_parts(packet.data, packet.caplen as usize) };
        let safe_packet = SafePacket::new(BytesMut::from(data), 0);
        
        // 将包添加到缓冲区
        if let Some(buffer) = PACKET_BUFFER.get() {
            if let Ok(mut buffer) = buffer.lock() {
                buffer.push_back(safe_packet);
                
                // 当缓冲区达到批处理大小时，进行批量处理
                if buffer.len() >= BATCH_SIZE {
                    let mut batch = BatchPacket::with_capacity(BATCH_SIZE, 0);
                    while let Some(packet) = buffer.pop_front() {
                        batch.add_packet(packet);
                    }
                    
                    if let Some(processor) = PROCESSOR_CELL.get() {
                        // 使用 tokio::spawn 在后台处理批次
                        let processor = processor.clone();
                        let batch_packets = batch.packets.clone();
                        let batch_timestamp = batch.timestamp;
                        tokio::spawn(async move {
                            let new_batch = BatchPacket::new(batch_packets, batch_timestamp);
                            if let Err(e) = processor.process_batch(new_batch).await {
                                error!("处理批次失败: {}", e);
                            }
                        });
                    }
                }
            }
        }
    }
    
    flag
}

// 错误回调函数
extern "C" fn test_error_callback(error: *const c_char, user_data: *mut c_void) {
    if !error.is_null() {
        let error_str = unsafe { CStr::from_ptr(error) };
        if let Ok(error_msg) = error_str.to_str() {
            error!("[Rust] 捕获错误: {}", error_msg);
        }
    }
}

#[tokio::test]
async fn test_capture_start_stop() {
    let running = Arc::new(AtomicBool::new(true));
    let running_ptr = Arc::into_raw(running.clone()) as *mut c_void;
    
    // 初始化捕获
    let config = CaptureConfig {
        device: CString::new("lo").unwrap().into_raw(),
        filter: CString::new("").unwrap().into_raw(),
        snaplen: 65535,
        timeout_ms: 1000,
        promiscuous: false,
        immediate: true,
        buffer_size: 1024 * 1024,
        backend_type: CaptureBackendType::Pcap,
    };
    
    let handle = unsafe { capture_init(&config, test_error_callback, running_ptr) };
    assert!(!handle.is_null(), "捕获初始化失败");
    
    // 启动捕获
    let result = unsafe {
        capture_start(
            handle,
            test_packet_callback,
            running_ptr,
        )
    };
    assert!(result == 0, "启动捕获失败");
    
    // 等待一段时间
    sleep(Duration::from_secs(1)).await;
    
    // 停止捕获
    running.store(false, Ordering::Relaxed);
    unsafe { capture_stop(handle) };
    
    // 清理资源
    unsafe { capture_cleanup(handle) };
    
    // 清理配置
    unsafe {
        let _ = CString::from_raw(config.device as *mut c_char);
        let _ = CString::from_raw(config.filter as *mut c_char);
    }
}

#[tokio::test]
async fn test_full_pipeline() {
    // 初始化处理器
    let config = ShardConfig::default();
    let reassembler = Arc::new(ShardedTcpReassembler::new(config));
    let processor = Arc::new(PacketProcessor::new(reassembler));
    PROCESSOR_CELL.set(processor.clone()).ok();
    
    // 创建测试数据
    let payload = b"Hello, World!";
    let packet = create_test_tcp_packet(
        1,
        payload,
        0x18, // PSH | ACK
        "127.0.0.1",
        "127.0.0.1",
        1234,
        80,
    );
    
    // 创建批次
    let mut batch = BatchPacket::with_capacity(1, 0);
    batch.add_packet(packet);
    
    // 处理批次
    let result = processor.process_batch(batch).await;
    assert!(result.is_ok(), "批次处理失败: {:?}", result.err());
    
    // 验证结果
    let active_batches = processor.get_active_batches();
    assert_eq!(active_batches, 0, "活动批次数量不正确");
}

#[tokio::test]
async fn test_capture_error_handling() {
    let running = Arc::new(AtomicBool::new(true));
    let running_ptr = Arc::into_raw(running.clone()) as *mut c_void;
    
    // 使用无效的接口名称
    let config = CaptureConfig {
        device: CString::new("invalid_interface").unwrap().into_raw(),
        filter: CString::new("").unwrap().into_raw(),
        snaplen: 65535,
        timeout_ms: 1000,
        promiscuous: false,
        immediate: true,
        buffer_size: 1024 * 1024,
        backend_type: CaptureBackendType::Pcap,
    };
    
    let handle = unsafe { capture_init(&config, test_error_callback, running_ptr) };
    assert!(handle.is_null(), "使用无效接口应该返回空句柄");
    
    // 清理配置
    unsafe {
        let _ = CString::from_raw(config.device as *mut c_char);
        let _ = CString::from_raw(config.filter as *mut c_char);
    }
}

#[tokio::test]
async fn test_error_handling() {
    // 初始化处理器
    let config = ShardConfig::default();
    let reassembler = Arc::new(ShardedTcpReassembler::new(config));
    let processor = Arc::new(PacketProcessor::new(reassembler));
    PROCESSOR_CELL.set(processor.clone()).ok();
    
    // 创建无效的测试数据
    let mut invalid_data = BytesMut::with_capacity(10);
    invalid_data.resize(10, 0);
    let packet = SafePacket::new(invalid_data, 0);
    
    // 创建批次
    let mut batch = BatchPacket::with_capacity(1, 0);
    batch.add_packet(packet);
    
    // 处理批次
    let result = processor.process_batch(batch).await;
    assert!(result.is_err(), "处理无效数据应该返回错误");
    
    // 检查活跃批次数量
    assert_eq!(processor.get_active_batches(), 0, "应该有0个活跃批次");
}

#[tokio::test]
async fn test_performance() {
    // 初始化处理器
    let config = ShardConfig::default();
    let reassembler = Arc::new(ShardedTcpReassembler::new(config));
    let processor = Arc::new(PacketProcessor::new(reassembler));
    PROCESSOR_CELL.set(processor.clone()).ok();
    
    // 创建大量测试数据
    let mut batch = BatchPacket::with_capacity(1000, 0);
    for i in 0..1000 {
        let payload = format!("Test packet {}", i).into_bytes();
        let packet = create_test_tcp_packet(
            i as u32,
            &payload,
            0x18,
            "127.0.0.1",
            "127.0.0.1",
            1234,
            80,
        );
        batch.add_packet(packet);
    }
    
    // 测量处理时间
    let start = std::time::Instant::now();
    let result = processor.process_batch(batch).await;
    let duration = start.elapsed();
    
    assert!(result.is_ok(), "性能测试失败: {:?}", result.err());
    assert!(duration < Duration::from_secs(1), "处理时间过长: {:?}", duration);
    
    // 检查活跃批次数量
    assert_eq!(processor.get_active_batches(), 0, "应该有0个活跃批次");
}

#[tokio::test]
async fn test_batch_processing() {
    // 初始化处理器和缓冲区
    let config = ShardConfig::default();
    let reassembler = Arc::new(ShardedTcpReassembler::new(config));
    let processor = Arc::new(PacketProcessor::new(reassembler));
    PROCESSOR_CELL.set(processor.clone()).ok();
    init_packet_buffer();
    
    // 创建测试数据
    let mut packets = Vec::new();
    for i in 0..BATCH_SIZE {
        let payload = format!("Test packet {}", i).into_bytes();
        let packet = create_test_tcp_packet(
            i as u32,
            &payload,
            0x18,
            "127.0.0.1",
            "127.0.0.1",
            1234,
            80,
        );
        packets.push(packet);
    }
    
    // 模拟包捕获回调
    for packet in packets {
        let capture_packet = CapturePacket {
            data: packet.data.as_ptr(),
            caplen: packet.data.len() as u32,
            len: packet.data.len() as u32,
            ts: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            if_index: 0,
            flags: 0,
            protocol: 0,
            vlan_tci: 0,
            hash: 0,
        };
        
        // 调用回调函数
        let running = AtomicBool::new(true);
        test_packet_callback(&capture_packet, &running as *const AtomicBool as *mut c_void);
    }
    
    // 等待处理完成
    sleep(Duration::from_millis(100)).await;
    
    // 检查活跃批次数量
    assert_eq!(processor.get_active_batches(), 0, "应该有0个活跃批次");
} 