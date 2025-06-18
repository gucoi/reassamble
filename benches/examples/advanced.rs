use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;
use bytes::BytesMut;
use rust_core::{SafePacket, init_memory_pool, DecodedPacket};
use rust_core::decode::{IpHeader, TransportProtocol};
use rust_core::defrag::IpDefragmenter;
use rust_core::stream::{ShardedTcpReassembler, ShardConfig};
use std::sync::Arc;

// 创建一个模拟的IPv4数据包
fn create_ipv4_packet() -> SafePacket {
    let mut data = BytesMut::with_capacity(54);
    
    // 以太网头部 (14 bytes)
    data.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // 目的MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  // 源MAC
        0x08, 0x00,                           // IPv4类型
    ]);
    
    // IPv4头部 (20 bytes)
    data.extend_from_slice(&[
        0x45, 0x00,                           // 版本(4)和头长度(5*4=20)
        0x00, 0x28,                           // 总长度 (40 bytes)
        0x00, 0x01,                           // 标识
        0x00, 0x00,                           // 标志和片偏移
        0x40, 0x06,                           // TTL和协议(TCP=6)
        0x00, 0x00,                           // 头部校验和
        0xc0, 0xa8, 0x00, 0x01,               // 源IP (192.168.0.1)
        0xc0, 0xa8, 0x00, 0x02,               // 目的IP (192.168.0.2)
    ]);
    
    // TCP头部 (20 bytes)
    data.extend_from_slice(&[
        0x13, 0x88, 0x00, 0x50,               // 源端口 (5000), 目的端口 (80)
        0x00, 0x00, 0x00, 0x01,               // 序列号
        0x00, 0x00, 0x00, 0x00,               // 确认序号
        0x50, 0x02,                           // 数据偏移和标志 (SYN)
        0x71, 0x10,                           // 窗口大小
        0x00, 0x00, 0x00, 0x00,               // 校验和和紧急指针
    ]);
    
    // 测试数据
    data.extend_from_slice(b"TEST");
    
    SafePacket::new(data, 12345678)
}

// 创建模拟的IP分片数据包
fn create_ip_fragment(id: u16, offset: u16, more_fragments: bool, data: &[u8]) -> SafePacket {
    let mut packet = BytesMut::with_capacity(34 + data.len());
    
    // 以太网头部 (14 bytes)
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // 目的MAC
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  // 源MAC
        0x08, 0x00,                           // IPv4类型
    ]);
    
    // 设置分片标志
    let flag_offset = if more_fragments {
        0x2000 | offset // 设置更多分片标志(0x2000)
    } else {
        offset // 最后一个分片没有更多分片标志
    };
    
    // IP头部 (20 bytes)
    packet.extend_from_slice(&[
        0x45, 0x00,                                      // 版本和头部长度
        ((20 + data.len()) >> 8) as u8,                  // 总长度高字节
        ((20 + data.len()) & 0xff) as u8,                // 总长度低字节
        (id >> 8) as u8, id as u8,                       // 分片ID
        ((flag_offset >> 8) & 0xff) as u8,               // 标志和片偏移高字节
        (flag_offset & 0xff) as u8,                      // 片偏移低字节
        0x40, 0x06,                                      // TTL和协议(TCP)
        0x00, 0x00,                                      // 头部校验和
        0xc0, 0xa8, 0x00, 0x01,                          // 源IP (192.168.0.1)
        0xc0, 0xa8, 0x00, 0x02,                          // 目的IP (192.168.0.2)
    ]);
    
    // 添加分片数据
    packet.extend_from_slice(data);
    
    SafePacket::new(packet, 12345678)
}

// 测试本地创建的IP头部信息
fn test_ip_header_creation() -> bool {
    // 创建一个IP头部
    let header = IpHeader {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 1234,
        flags: 0,
        more_fragments: false,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,  // TCP
        header_checksum: 0,
        source_ip: 0xc0a80001,  // 192.168.0.1
        dest_ip: 0xc0a80002,    // 192.168.0.2
    };
    
    // 验证字段
    header.version == 4 && 
    header.ihl == 5 && 
    header.total_length == 40 &&
    header.protocol == 6
}

// 测试创建一个完整的解码数据包
fn test_create_decoded_packet() -> bool {
    let ip_header = IpHeader {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 1234,
        flags: 0,
        more_fragments: false,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,  // TCP
        header_checksum: 0,
        source_ip: 0xc0a80001,  // 192.168.0.1
        dest_ip: 0xc0a80002,    // 192.168.0.2
    };
    
    let protocol = TransportProtocol::TCP {
        src_port: 5000,
        dst_port: 80,
        seq: 1,
        ack: 0,
        flags: 2,  // SYN
        window: 0x7110,
        payload: BytesMut::from(&b"TEST"[..]),
    };
    
    let packet = DecodedPacket {
        ip_header,
        protocol,
        timestamp: 12345678,
        payload: b"TEST".to_vec(),
    };
    
    // 验证字段
    match &packet.protocol {
        TransportProtocol::TCP { src_port, dst_port, .. } => {
            *src_port == 5000 && *dst_port == 80 && packet.timestamp == 12345678
        },
        _ => false,
    }
}

// 测试IP分片重组器的创建
fn test_create_defragmenter() -> bool {
    let defrag = IpDefragmenter::new();
    // 这只是一个简单的测试，确保能成功创建对象
    true
}

// 测试TCP重组器的创建
fn test_create_tcp_reassembler() -> bool {
    let config = ShardConfig::default();
    let reassembler = ShardedTcpReassembler::new(config);
    
    // 验证基本属性
    reassembler.get_health_status().is_ok()
}

// 基准测试
fn benchmark_advanced_components(c: &mut Criterion) {
    // 确保初始化内存池
    init_memory_pool();
    
    let mut group = c.benchmark_group("advanced_components");
    group.measurement_time(Duration::from_secs(1));
    group.sample_size(10);
    
    // 测试创建IP头部
    group.bench_function("ip_header_creation", |b| {
        b.iter(|| {
            assert!(test_ip_header_creation());
        });
    });
    
    // 测试创建完整的解码数据包
    group.bench_function("decoded_packet_creation", |b| {
        b.iter(|| {
            assert!(test_create_decoded_packet());
        });
    });
    
    // 测试IP分片重组器创建
    group.bench_function("defragmenter_creation", |b| {
        b.iter(|| {
            assert!(test_create_defragmenter());
        });
    });
    
    // 测试TCP重组器创建
    group.bench_function("tcp_reassembler_creation", |b| {
        b.iter(|| {
            assert!(test_create_tcp_reassembler());
        });
    });
    
    group.finish();
}

// 测试生成各类数据包
fn benchmark_packet_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_creation");
    group.measurement_time(Duration::from_secs(1));
    group.sample_size(10);
    
    // 测试创建IPv4数据包
    group.bench_function("create_ipv4_packet", |b| {
        b.iter(|| {
            let packet = create_ipv4_packet();
            assert!(packet.data.len() > 0);
        });
    });
    
    // 测试创建IP分片数据包
    group.bench_function("create_ip_fragment", |b| {
        b.iter(|| {
            let fragment1 = create_ip_fragment(1234, 0, true, b"First fragment");
            let fragment2 = create_ip_fragment(1234, 184, false, b"Last fragment");
            assert!(fragment1.data.len() > 0 && fragment2.data.len() > 0);
        });
    });
    
    group.finish();
}

criterion_group!(benches, benchmark_advanced_components, benchmark_packet_creation);
criterion_main!(benches); 