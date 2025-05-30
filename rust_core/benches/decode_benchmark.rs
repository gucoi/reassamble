use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rust_core::decode::{decode_packet, decode_packet_with_buffer};
use rust_core::SafePacket;
use rand::Rng;
use std::hint::black_box;
use std::time::Duration;
use bytes::BytesMut;

// 生成随机测试数据包
fn generate_test_packet(size: usize) -> SafePacket {
    let mut rng = rand::rng();
    let mut data = BytesMut::with_capacity(size);
    data.resize(size, 0);
    
    // 填充以太网头部 (14字节)
    data[0..6].fill(0x00);  // 目标MAC
    data[6..12].fill(0x00); // 源MAC
    data[12..14].fill(0x08); // 类型 (IPv4)
    
    // 填充IP头部 (20字节)
    data[14] = 0x45;  // 版本(4) + IHL(5)
    data[15] = 0x00;  // 服务类型
    let total_length = (size as u16).to_be_bytes();
    data[16..18].copy_from_slice(&total_length);
    data[18..20].fill(0x00); // 标识
    data[20] = 0x40;  // 标志 + 片偏移
    data[21] = 0x00;  // 片偏移
    data[22] = 0x40;  // TTL
    data[23] = 0x06;  // 协议 (TCP)
    data[24..26].fill(0x00); // 校验和
    data[26..30].fill(0x7f); // 源IP (127.0.0.1)
    data[30..34].fill(0x7f); // 目标IP (127.0.0.1)
    
    // 填充TCP头部 (20字节)
    data[34..36].fill(0x00); // 源端口
    data[36..38].fill(0x00); // 目标端口
    rng.fill(&mut data[38..42]); // 序列号
    rng.fill(&mut data[42..46]); // 确认号
    data[46] = 0x50;  // 数据偏移
    data[47] = 0x02;  // 标志 (SYN)
    data[48..50].fill(0x20); // 窗口大小
    data[50..52].fill(0x00); // 校验和
    data[52..54].fill(0x00); // 紧急指针
    
    // 填充payload
    rng.fill(&mut data[54..]);
    
    SafePacket::new(data, 0)
}

// 生成带有TCP选项的测试数据包
fn generate_test_packet_with_options(size: usize) -> SafePacket {
    let mut rng = rand::rng();
    let mut data = BytesMut::with_capacity(size);
    data.resize(size, 0);
    
    // 填充以太网头部 (14字节)
    data[0..6].fill(0x00);  // 目标MAC
    data[6..12].fill(0x00); // 源MAC
    data[12..14].fill(0x08); // 类型 (IPv4)
    
    // 填充IP头部 (20字节)
    data[14] = 0x45;  // 版本(4) + IHL(5)
    data[15] = 0x00;  // 服务类型
    let total_length = (size as u16).to_be_bytes();
    data[16..18].copy_from_slice(&total_length);
    data[18..20].fill(0x00); // 标识
    data[20] = 0x40;  // 标志 + 片偏移
    data[21] = 0x00;  // 片偏移
    data[22] = 0x40;  // TTL
    data[23] = 0x06;  // 协议 (TCP)
    data[24..26].fill(0x00); // 校验和
    data[26..30].fill(0x7f); // 源IP (127.0.0.1)
    data[30..34].fill(0x7f); // 目标IP (127.0.0.1)
    
    // 填充TCP头部 (20字节)
    data[34..36].fill(0x00); // 源端口
    data[36..38].fill(0x00); // 目标端口
    rng.fill(&mut data[38..42]); // 序列号
    rng.fill(&mut data[42..46]); // 确认号
    data[46] = 0x60;  // 数据偏移 (24字节，包含选项)
    data[47] = 0x02;  // 标志 (SYN)
    data[48..50].fill(0x20); // 窗口大小
    data[50..52].fill(0x00); // 校验和
    data[52..54].fill(0x00); // 紧急指针
    
    // 添加TCP选项
    data[54] = 0x02; // MSS选项
    data[55] = 0x04; // 长度
    data[56..58].copy_from_slice(&(1460u16).to_be_bytes()); // MSS值
    
    data[58] = 0x01; // NOP选项
    data[59] = 0x03; // 窗口缩放选项
    data[60] = 0x03; // 长度
    data[61] = 0x07; // 窗口缩放因子
    
    // 填充payload
    rng.fill(&mut data[62..]);
    
    SafePacket::new(data, 0)
}

// 生成分片IP数据包
fn generate_fragmented_packet(size: usize) -> Vec<SafePacket> {
    let mut rng = rand::rng();
    let mut packets = Vec::new();
    let fragment_size = 1480; // 每个分片的最大大小
    let num_fragments = (size + fragment_size - 1) / fragment_size;
    
    for i in 0..num_fragments {
        let mut data = BytesMut::with_capacity(fragment_size + 34);
        data.resize(fragment_size + 34, 0);
        
        // 填充以太网头部
        data[0..6].fill(0x00);
        data[6..12].fill(0x00);
        data[12..14].fill(0x08);
        
        // 填充IP头部
        data[14] = 0x45;
        data[15] = 0x00;
        let fragment_length = if i == num_fragments - 1 {
            size - i * fragment_size + 34
        } else {
            fragment_size + 34
        };
        data[16..18].copy_from_slice(&(fragment_length as u16).to_be_bytes());
        data[18..20].copy_from_slice(&(i as u16).to_be_bytes());
        data[20] = if i == num_fragments - 1 { 0x40 } else { 0x20 }; // 最后一个分片没有MF标志
        data[21] = ((i * fragment_size / 8) as u8);
        data[22] = 0x40;
        data[23] = 0x06;
        data[24..26].fill(0x00);
        data[26..30].fill(0x7f);
        data[30..34].fill(0x7f);
        
        // 填充payload
        let start = i * fragment_size;
        let end = std::cmp::min(start + fragment_size, size);
        rng.fill(&mut data[34..34 + end - start]);
        
        packets.push(SafePacket::new(data, 0));
    }
    
    packets
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_packet");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);
    
    // 测试不同大小的数据包
    let packet_sizes = [64, 128, 256, 512, 1024, 1500];
    let mut buffer = Vec::with_capacity(2048);
    
    for size in packet_sizes.iter() {
        let packet = generate_test_packet(*size);
        
        group.bench_with_input(
            BenchmarkId::new("original", size),
            &packet,
            |b, p| b.iter(|| black_box(decode_packet(p)))
        );
        
        group.bench_with_input(
            BenchmarkId::new("optimized", size),
            &packet,
            |b, p| b.iter(|| {
                buffer.clear();
                black_box(decode_packet_with_buffer(p, &mut buffer))
            })
        );
    }
    
    // 测试带有TCP选项的数据包
    let option_packet = generate_test_packet_with_options(1500);
    group.bench_with_input(
        BenchmarkId::new("with_options", "1500"),
        &option_packet,
        |b, p| b.iter(|| {
            buffer.clear();
            black_box(decode_packet_with_buffer(p, &mut buffer))
        })
    );
    
    // 测试分片数据包
    let fragmented_packets = generate_fragmented_packet(3000);
    group.bench_with_input(
        BenchmarkId::new("fragmented", "3000"),
        &fragmented_packets,
        |b, packets| b.iter(|| {
            buffer.clear();
            for packet in packets {
                let _ = black_box(decode_packet_with_buffer(packet, &mut buffer));
            }
        })
    );
    
    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches); 