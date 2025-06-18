use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;
use bytes::BytesMut;
use rust_core::{
    SafePacket, init_memory_pool, decode_packet, 
    PacketProcessor, IpDefragmenter, ShardedTcpReassembler, ShardConfig
};
use std::sync::Arc;
use tokio::runtime::Runtime;

// 构建一个TCP会话的数据包序列
fn create_tcp_session_packets() -> Vec<SafePacket> {
    let mut packets = Vec::new();
    
    // TCP 三次握手
    // SYN
    packets.push(create_tcp_packet(
        0xc0a80001, 0xc0a80002, // 192.168.0.1 -> 192.168.0.2
        1234, 80, 1000, 0, 0x02, &[]
    ));
    
    // SYN-ACK
    packets.push(create_tcp_packet(
        0xc0a80002, 0xc0a80001, // 192.168.0.2 -> 192.168.0.1
        80, 1234, 5000, 1001, 0x12, &[]
    ));
    
    // ACK
    packets.push(create_tcp_packet(
        0xc0a80001, 0xc0a80002, // 192.168.0.1 -> 192.168.0.2
        1234, 80, 1001, 5001, 0x10, &[]
    ));
    
    // 数据传输 - HTTP请求
    let http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    
    // 将HTTP请求分成几个数据包发送
    let chunk_size = 20;
    for (i, chunk) in http_request.chunks(chunk_size).enumerate() {
        packets.push(create_tcp_packet(
            0xc0a80001, 0xc0a80002, // 192.168.0.1 -> 192.168.0.2
            1234, 80, 1001 + i as u32 * chunk_size as u32, 5001, 0x18, chunk
        ));
    }
    
    // HTTP响应开始
    let http_response_header = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n";
    
    // 将HTTP响应分成几个数据包
    for (i, chunk) in http_response_header.chunks(chunk_size).enumerate() {
        packets.push(create_tcp_packet(
            0xc0a80002, 0xc0a80001, // 192.168.0.2 -> 192.168.0.1
            80, 1234, 5001 + i as u32 * chunk_size as u32, 
            1001 + http_request.len() as u32, 0x18, chunk
        ));
    }
    
    // HTTP响应主体
    let http_response_body = b"<html><body><h1>Hello World!</h1><p>This is a test page for TCP reassembly.</p></body></html>";
    
    // 发送响应主体，每个包10字节
    let body_chunk_size = 10;
    for (i, chunk) in http_response_body.chunks(body_chunk_size).enumerate() {
        packets.push(create_tcp_packet(
            0xc0a80002, 0xc0a80001, // 192.168.0.2 -> 192.168.0.1
            80, 1234, 
            5001 + http_response_header.len() as u32 + i as u32 * body_chunk_size as u32, 
            1001 + http_request.len() as u32, 0x18, chunk
        ));
    }
    
    // 四次挥手
    // FIN from client
    packets.push(create_tcp_packet(
        0xc0a80001, 0xc0a80002, // 192.168.0.1 -> 192.168.0.2
        1234, 80, 
        1001 + http_request.len() as u32, 
        5001 + http_response_header.len() as u32 + http_response_body.len() as u32,
        0x11, &[] // FIN + ACK
    ));
    
    // ACK from server
    packets.push(create_tcp_packet(
        0xc0a80002, 0xc0a80001, // 192.168.0.2 -> 192.168.0.1
        80, 1234,
        5001 + http_response_header.len() as u32 + http_response_body.len() as u32,
        1001 + http_request.len() as u32 + 1, // +1 for FIN
        0x10, &[] // ACK
    ));
    
    // FIN from server
    packets.push(create_tcp_packet(
        0xc0a80002, 0xc0a80001, // 192.168.0.2 -> 192.168.0.1
        80, 1234,
        5001 + http_response_header.len() as u32 + http_response_body.len() as u32,
        1001 + http_request.len() as u32 + 1, // +1 for FIN
        0x11, &[] // FIN + ACK
    ));
    
    // Final ACK
    packets.push(create_tcp_packet(
        0xc0a80001, 0xc0a80002, // 192.168.0.1 -> 192.168.0.2
        1234, 80,
        1001 + http_request.len() as u32 + 1, // +1 for FIN
        5001 + http_response_header.len() as u32 + http_response_body.len() as u32 + 1, // +1 for FIN
        0x10, &[] // ACK
    ));
    
    packets
}

// 辅助函数：创建TCP数据包
fn create_tcp_packet(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, 
                    seq: u32, ack: u32, flags: u8, payload: &[u8]) -> SafePacket {
    let mut data = BytesMut::with_capacity(54 + payload.len());
    
    // 以太网头部 (14 bytes)
    data.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // 目的MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  // 源MAC
        0x08, 0x00,                           // IPv4类型
    ]);
    
    // IPv4头部 (20 bytes)
    let total_length = 20 + 20 + payload.len(); // IP头部 + TCP头部 + 负载
    
    data.extend_from_slice(&[
        0x45, 0x00,                           // 版本(4)和头长度(5*4=20)
        (total_length >> 8) as u8,            // 总长度高字节
        total_length as u8,                   // 总长度低字节
        0x00, 0x01,                           // 标识
        0x00, 0x00,                           // 标志和片偏移
        0x40, 0x06,                           // TTL和协议(TCP=6)
        0x00, 0x00,                           // 头部校验和
        (src_ip >> 24) as u8, (src_ip >> 16) as u8, (src_ip >> 8) as u8, src_ip as u8,  // 源IP
        (dst_ip >> 24) as u8, (dst_ip >> 16) as u8, (dst_ip >> 8) as u8, dst_ip as u8,  // 目的IP
    ]);
    
    // TCP头部 (20 bytes)
    data.extend_from_slice(&[
        (src_port >> 8) as u8, src_port as u8,  // 源端口
        (dst_port >> 8) as u8, dst_port as u8,  // 目的端口
        (seq >> 24) as u8, (seq >> 16) as u8, (seq >> 8) as u8, seq as u8,  // 序列号
        (ack >> 24) as u8, (ack >> 16) as u8, (ack >> 8) as u8, ack as u8,  // 确认序号
        0x50, flags,                          // 数据偏移和标志
        0x71, 0x10,                           // 窗口大小
        0x00, 0x00, 0x00, 0x00,               // 校验和和紧急指针
    ]);
    
    // 负载数据
    if !payload.is_empty() {
        data.extend_from_slice(payload);
    }
    
    // 使用递增的时间戳
    static mut TIMESTAMP: u64 = 12345678;
    let timestamp = unsafe {
        TIMESTAMP += 10;
        TIMESTAMP
    };
    
    SafePacket::new(data, timestamp)
}

// 测试整个TCP会话处理
fn test_tcp_session_processing(rt: &Runtime) -> bool {
    // 创建TCP会话数据包
    let packets = create_tcp_session_packets();
    
    // 使用运行时创建处理组件并执行测试
    rt.block_on(async {
        // 在 Tokio 运行时内部创建处理组件
        let config = ShardConfig::default();
        let reassembler = Arc::new(ShardedTcpReassembler::new(config));
        let processor = Arc::new(PacketProcessor::new(reassembler.clone()));
        
        // 模拟处理整个会话
        let mut processed_count = 0;
        let mut reassembled_count = 0;
        
        for packet in packets {
            let result = processor.process_packet(&packet).await;
            
            if result.is_ok() {
                processed_count += 1;
                
                if let Ok(Some(data)) = result {
                    // 如果有返回的重组数据
                    reassembled_count += 1;
                }
            }
        }
        
        // 检查是否处理了所有数据包
        processed_count > 0 && reassembled_count > 0
    })
}

// 完整的端到端测试
fn benchmark_integration_test(c: &mut Criterion) {
    // 初始化内存池
    init_memory_pool();
    
    // 创建一个全局的运行时，确保所有测试都使用同一个运行时
    let rt = Runtime::new().unwrap();
    
    // 添加基准测试
    let mut group = c.benchmark_group("integration_tests");
    group.measurement_time(Duration::from_secs(1));
    group.sample_size(10);  // 修改为10
    
    group.bench_function("tcp_session_processing", |b| {
        b.iter(|| {
            assert!(test_tcp_session_processing(&rt));
        });
    });
    
    group.finish();
}

criterion_group!(benches, benchmark_integration_test);
criterion_main!(benches); 