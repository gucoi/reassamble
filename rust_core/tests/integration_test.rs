use rust_core::{
    decode::{decode_packet, DecodedPacket, IpHeader, TransportProtocol},
    defrag::IpDefragmenter,
    stream::{ShardedTcpReassembler, ShardConfig, StreamStats},
    processor::PacketProcessor,
    ffi::capture::{capture_init, capture_start, capture_stop, capture_cleanup},
    ffi::types::{CaptureConfig, CaptureBackendType, CapturePacket},
    SafePacket,
    Result,
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

static PROCESSOR_CELL: OnceCell<Arc<PacketProcessor>> = OnceCell::new();
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

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
    let mut data = vec![0u8; 54 + payload.len()];
    
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
        
        let mut data = vec![0u8; 54 + fragment.len()];
        
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
        let safe_packet = SafePacket::new(data.to_vec(), 0);
        if let Some(processor) = PROCESSOR_CELL.get() {
            if let Some(rt) = RUNTIME.get() {
                let processor = processor.clone();
                rt.spawn(async move {
                    if let Err(e) = processor.process_packet(&safe_packet).await {
                        error!("[Rust] 处理数据包时出错: {:?}", e);
                    }
                });
            }
        }
    }
    flag
}

extern "C" fn test_error_callback(error: *const c_char, user_data: *mut c_void) {
    if error.is_null() {
        return;
    }
    let error_str = unsafe { CStr::from_ptr(error) };
    error!("Error: {}", error_str.to_string_lossy());
}

#[test]
fn test_capture_start_stop() {
    let running = Arc::new(AtomicBool::new(true));
    let running_ptr = Arc::into_raw(running.clone()) as *mut c_void;
    info!("[Rust] user_data ptr before pass to C: {:?}", running_ptr);
    
    // 初始化捕获
    let device = CString::new("lo").unwrap();
    let filter = CString::new("").unwrap();
    let config = CaptureConfig {
        device: device.as_ptr(),
        filter: filter.as_ptr(),
        snaplen: 65535,
        timeout_ms: 1000,
        promiscuous: false,
        immediate: true,
        buffer_size: 1024 * 1024,
        backend_type: CaptureBackendType::Pcap,
    };
    
    info!("Initializing capture with device: {}", device.to_string_lossy());
    let handle = unsafe {
        capture_init(
            &config,
            test_error_callback,
            running_ptr,
        )
    };
    assert!(!handle.is_null(), "Failed to initialize capture");
    
    // 启动捕获
    info!("Starting capture...");
    let result = unsafe { 
        capture_start(
            handle,
            test_packet_callback,
            running_ptr,
        ) 
    };
    assert_eq!(result, 0, "Failed to start capture");
    
    // 等待一段时间让捕获运行
    info!("Waiting for capture to run...");
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // 停止捕获
    info!("Stopping capture...");
    running.store(false, Ordering::Relaxed);
    info!("[Rust] after running.store(false), user_data ptr: {:?}", running_ptr);
    let result = unsafe { capture_stop(handle) };
    assert_eq!(result, 0, "Failed to stop capture");
    
    // 等待一段时间确保所有回调都完成
    info!("Waiting for callbacks to complete...");
    std::thread::sleep(std::time::Duration::from_secs(1));
    
    // 清理资源
    info!("Cleaning up resources...");
    info!("[Rust] before Arc::from_raw user_data ptr: {:?}", running_ptr);
    unsafe {
        capture_cleanup(handle);
        info!("[Rust] after capture_cleanup, about to Arc::from_raw user_data ptr: {:?}", running_ptr);
        let _ = Arc::from_raw(running_ptr as *const AtomicBool);
        info!("[Rust] after Arc::from_raw user_data ptr: {:?}", running_ptr);
    }
    info!("Test completed successfully");
}

#[tokio::test]
async fn test_full_pipeline() {
    // 1. 初始化抓包
    let device = CString::new("lo").unwrap();
    let filter = CString::new("").unwrap();
    let config = CaptureConfig {
        device: device.as_ptr(),
        filter: filter.as_ptr(),
        snaplen: 65535,
        timeout_ms: 1000,
        promiscuous: false,
        immediate: true,
        buffer_size: 1024 * 1024,
        backend_type: CaptureBackendType::Pcap,
    };

    let running = Arc::new(AtomicBool::new(true));
    let running_ptr = Arc::into_raw(running.clone()) as *mut c_void;

    // 全局唯一 reassembler/processor
    let shard_config = ShardConfig::default();
    let reassembler = Arc::new(ShardedTcpReassembler::new(shard_config));
    let processor = Arc::new(PacketProcessor::new(reassembler.clone()));
    PROCESSOR_CELL.set(processor.clone()).ok();
    RUNTIME.set(Runtime::new().unwrap()).ok();

    let handle = unsafe {
        capture_init(
            &config,
            test_error_callback,
            running_ptr,
        )
    };
    assert!(!handle.is_null(), "Failed to initialize capture");

    // 2. 启动抓包
    let result = unsafe { 
        capture_start(
            handle,
            test_packet_callback,
            running_ptr,
        ) 
    };
    assert_eq!(result, 0, "Failed to start capture");

    // 等待抓包线程初始化
    sleep(Duration::from_millis(100)).await;

    // 等待一段时间让抓包线程捕获一些数据包
    sleep(Duration::from_secs(2)).await;

    // 3. 检查统计信息
    let stats = reassembler.get_shard_stats();
    let total_streams: usize = stats.iter().sum();
    assert!(total_streams > 0, "没有检测到任何流"); // 至少有一个流被重组

    // 4. 停止抓包
    running.store(false, Ordering::Relaxed);
    let result = unsafe { capture_stop(handle) };
    assert_eq!(result, 0, "Failed to stop capture");

    // 5. 清理资源
    sleep(Duration::from_secs(1)).await;
    let cleanup_result = reassembler.cleanup_all();
    assert!(cleanup_result.is_ok());

    // 6. 关闭重组器
    let shutdown_result = reassembler.shutdown();
    assert!(shutdown_result.is_ok());

    // 7. 清理抓包资源
    unsafe {
        capture_cleanup(handle);
        let _ = Arc::from_raw(running_ptr as *const AtomicBool);
    }
}

#[tokio::test]
async fn test_capture_error_handling() {
    // 1. 测试无效设备
    let device = CString::new("invalid_device").unwrap();
    let filter = CString::new("").unwrap();
    
    let config = CaptureConfig {
        device: device.as_ptr(),
        filter: filter.as_ptr(),
        snaplen: 65535,
        timeout_ms: 1000,
        promiscuous: false,
        immediate: true,
        buffer_size: 1024 * 1024,
        backend_type: CaptureBackendType::Pcap,
    };

    let handle = unsafe {
        capture_init(
            &config,
            test_error_callback,
            std::ptr::null_mut(),
        )
    };
    assert!(handle.is_null());

    // 2. 测试无效过滤器
    let device = CString::new("lo").unwrap();
    let filter = CString::new("invalid filter").unwrap();
    
    let config = CaptureConfig {
        device: device.as_ptr(),
        filter: filter.as_ptr(),
        snaplen: 65535,
        timeout_ms: 1000,
        promiscuous: false,
        immediate: true,
        buffer_size: 1024 * 1024,
        backend_type: CaptureBackendType::Pcap,
    };

    let handle = unsafe {
        capture_init(
            &config,
            test_error_callback,
            std::ptr::null_mut(),
        )
    };
    assert!(handle.is_null());
}

#[tokio::test]
async fn test_error_handling() {
    let config = ShardConfig::default();
    let reassembler = Arc::new(ShardedTcpReassembler::new(config));
    let processor = PacketProcessor::new(reassembler.clone());
    
    // 1. 测试无效数据包
    let invalid_packet = SafePacket::new(vec![0u8; 10], 0);
    let result = processor.process_packet(&invalid_packet).await;
    assert!(result.is_err());
    
    // 2. 测试超时处理
    let config = ShardConfig {
        timeout_secs: 1,
        ..Default::default()
    };
    let reassembler = Arc::new(ShardedTcpReassembler::new(config));
    let processor = PacketProcessor::new(reassembler.clone());
    
    let packet = create_test_tcp_packet(
        1,
        b"Test",
        0x18,
        "192.168.1.1",
        "192.168.1.2",
        1234,
        80,
    );
    
    let result = processor.process_packet(&packet).await;
    assert!(result.is_ok());
    
    // 等待超时
    sleep(Duration::from_secs(2)).await;
    
    // 清理应该移除超时的流
    let cleanup_result = reassembler.cleanup_all();
    assert!(cleanup_result.is_ok());
    
    let stats = reassembler.get_shard_stats();
    assert!(stats.is_empty());
}

#[tokio::test]
async fn test_performance() {
    let config = ShardConfig {
        shard_count: 4,
        ..Default::default()
    };
    let reassembler = Arc::new(ShardedTcpReassembler::new(config));
    let processor = PacketProcessor::new(reassembler.clone());
    
    // 创建大量测试包
    let mut packets = Vec::new();
    for i in 0..1000 {
        let payload = format!("Test packet {}", i).into_bytes();
        let packet = create_test_tcp_packet(
            i as u32,
            &payload,
            0x18,
            "192.168.1.1",
            "192.168.1.2",
            1234,
            80,
        );
        packets.push(packet);
    }
    
    // 并发处理所有包
    let start = std::time::Instant::now();
    let processor = Arc::new(processor);
    let results = futures::future::join_all(
        packets.into_iter().map(|p| {
            let packet = p.clone();
            let processor = processor.clone();
            async move {
                processor.process_packet(&packet).await
            }
        })
    ).await;
    
    let duration = start.elapsed();
    println!("处理1000个包用时: {:?}", duration);
    
    // 验证结果
    for result in results {
        assert!(result.is_ok());
    }
    
    // 检查统计信息
    let stats = reassembler.get_shard_stats();
    assert!(!stats.is_empty());
} 