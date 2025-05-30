use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rust_core::decode::{decode_packet, decode_packet_with_buffer};
use rust_core::SafePacket;
use rand::Rng;
use std::time::Duration;

// 生成随机测试数据包
fn generate_test_packet(size: usize) -> SafePacket {
    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; size];
    
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

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_packet");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);
    
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
    
    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches); 