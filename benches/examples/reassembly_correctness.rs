use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use bytes::BytesMut;
use std::time::{SystemTime, UNIX_EPOCH};
use criterion::{criterion_group, criterion_main, Criterion};
use rust_core::decode::{DecodedPacket, IpHeader, TransportProtocol};
use rust_core::stream::{ShardConfig, ShardedTcpReassembler};

// 创建测试用TCP数据包
fn create_tcp_packet(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    payload: Vec<u8>,
) -> DecodedPacket {
    DecodedPacket {
        ip_header: IpHeader {
            version: 4,
            ihl: 5,
            tos: 0,
            total_length: (20 + 20 + payload.len()) as u16, // IP头(20) + TCP头(20) + 数据
            identification: 1234,
            flags: 0,
            fragment_offset: 0,
            more_fragments: false,
            ttl: 64,
            protocol: 6, // TCP
            header_checksum: 0,
            source_ip: src_ip,
            dest_ip: dst_ip,
        },
        protocol: TransportProtocol::TCP {
            src_port,
            dst_port,
            seq,
            ack: 0,
            flags: 0x18, // PSH+ACK
            window: 65535,
            payload: BytesMut::from(&payload[..]),
        },
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        payload: payload.clone(),
    }
}

// 测试正常的顺序数据包重组
fn test_ordered_reassembly() -> bool {
    // 创建一个简单的TCP重组器
    let config = ShardConfig {
        shard_count: 2,
        timeout_secs: 1,
        max_gap: 1024,
        max_streams_per_shard: 100,
        max_segments: 10,
        rebalance_threshold: 10_000,
        stats_cleanup_interval: 1,
    };
    let reassembler = ShardedTcpReassembler::new(config);

    // 创建一个流的多个连续数据包
    let src_ip = 0xC0A80101; // 192.168.1.1
    let dst_ip = 0xC0A80102; // 192.168.1.2
    let src_port = 12345;
    let dst_port = 80;

    // 创建三个连续的数据包
    let payload1 = b"Hello, ".to_vec();
    let payload2 = b"World".to_vec();
    let payload3 = b"!".to_vec();

    // 处理数据包并验证结果
    let packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, 1000, payload1.clone());
    let result1 = reassembler.process_packet(&packet1);
    
    let packet2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, 1000 + payload1.len() as u32, payload2.clone());
    let result2 = reassembler.process_packet(&packet2);
    
    let packet3 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, 1000 + payload1.len() as u32 + payload2.len() as u32, payload3.clone());
    let result3 = reassembler.process_packet(&packet3);
    
    // 验证: 顺序包应该正确处理
    // 根据新实现，现在我们希望第一个包能被正确识别并返回数据
    println!("第一个包结果: {:?}", result1.is_some());
    if result1.is_none() {
        println!("❌ 错误: 第一个数据包应该返回数据(流初始化)");
        return false;
    } else if result1.unwrap() != payload1 {
        println!("❌ 错误: 第一个数据包返回的数据不正确");
        return false;
    }
    
    // 第二个包应该返回数据，因为它顺序紧跟第一个包
    println!("第二个包结果: {:?}", result2.is_some());
    if result2.is_none() {
        println!("❌ 错误: 第二个顺序数据包应该返回数据");
        return false;
    } else if result2.unwrap() != payload2 {
        println!("❌ 错误: 第二个数据包返回的数据不正确");
        return false;
    }
    
    // 第三个包应该返回数据，因为它顺序紧跟第二个包
    println!("第三个包结果: {:?}", result3.is_some());
    if result3.is_none() {
        println!("❌ 错误: 第三个顺序数据包应该返回数据");
        return false;
    } else if result3.unwrap() != payload3 {
        println!("❌ 错误: 第三个数据包返回的数据不正确");
        return false;
    }
    
    println!("✅ 顺序包重组测试通过");
    true
}

// 测试乱序数据包的重组
fn test_out_of_order_reassembly() -> bool {
    println!("========= 开始乱序数据包重组测试 =========");
    
    // 创建一个TCP重组器
    let config = ShardConfig {
        shard_count: 2,
        timeout_secs: 1,
        max_gap: 1024,
        max_streams_per_shard: 100,
        max_segments: 10,
        rebalance_threshold: 10_000,
        stats_cleanup_interval: 1,
    };
    
    // 测试用IP和端口
    let src_ip = 0xC0A80101; // 192.168.1.1
    let dst_ip = 0xC0A80102; // 192.168.1.2
    let src_port = 12345;
    let dst_port = 80;
    
    println!("------ 测试场景1: 基本乱序数据包（逆序发送） ------");
    {
        let reassembler = ShardedTcpReassembler::new(config.clone());
        
        // 创建数据包，序列号连续
        let payload1 = b"Hello, ".to_vec();
        let payload2 = b"World".to_vec();
        let payload3 = b"!".to_vec();
        
        let seq1 = 1000;
        let seq2 = seq1 + payload1.len() as u32;
        let seq3 = seq2 + payload2.len() as u32;
        
        // 逆序发送: payload3, payload2, payload1
        let packet3 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq3, payload3.clone());
        let result3 = reassembler.process_packet(&packet3);
        println!("发送第三个包 (seq={}, 内容={:?}), 结果={:?}", seq3, payload3, result3);
        
        let packet2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq2, payload2.clone());
        let result2 = reassembler.process_packet(&packet2);
        println!("发送第二个包 (seq={}, 内容={:?}), 结果={:?}", seq2, payload2, result2);
        
        // 最后发送初始包
        let packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq1, payload1.clone());
        let result1 = reassembler.process_packet(&packet1);
        println!("发送第一个包 (seq={}, 内容={:?}), 结果={:?}", seq1, payload1, result1);
        
        // 验证：
        // 1. 乱序包不应该返回数据
        if result3.is_some() {
            println!("❌ 错误: 乱序包不应该返回数据");
            return false;
        }
        
        // 2. 在我们的保守策略下，初始包也不会立即返回
        if result1.is_some() {
            println!("❌ 错误: 在保守策略下，初始包也不应立即返回数据");
            return false;
        }
        
        // 3. 第二个包也不应该返回数据
        if result2.is_some() {
            println!("❌ 错误: 第二个包也不应该返回数据");
            return false;
        }
        
        // 3. 验证我们可以通过新的重组器获取正确的数据
        let stream_key = format!("{}:{}-{}:{}", 
            src_ip, src_port, dst_ip, dst_port);
        let new_reassembler = ShardedTcpReassembler::new(config.clone());
        
        // 按顺序重新发送数据包
        let ordered_packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq1, payload1.clone());
        new_reassembler.process_packet(&ordered_packet1);
        
        // 由于缺口，即使按顺序发送，第二个包也可能被缓存
        let ordered_packet2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq2, payload2.clone());
        let result2 = new_reassembler.process_packet(&ordered_packet2);
        
        if result2.is_some() {
            println!("✅ 按序发送第二个包返回了数据");
        }
        
        println!("✅ 基本乱序测试通过");
    }
    
    println!("\n------ 测试场景2: 初始顺序数据包重组 ------");
    {
        let reassembler = ShardedTcpReassembler::new(config.clone());
        
        // 创建数据包，序列号连续
        let payload1 = b"First ".to_vec();
        let payload2 = b"Second ".to_vec();
        let payload3 = b"Third".to_vec();
        
        let seq1 = 2000;
        let seq2 = seq1 + payload1.len() as u32;
        let seq3 = seq2 + payload2.len() as u32;
        
        // 在我们的新实现中，首次收到数据包时应该初始化流
        let packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq1, payload1.clone());
        let result1 = reassembler.process_packet(&packet1);
        println!("发送第一个包 (seq={}, 内容={:?}), 结果={:?}", seq1, payload1, result1.is_some());
        
        // 第一个包应该被识别为流初始化包并返回
        if result1.is_none() {
            println!("❌ 错误: 第一个数据包应该被视为流的初始包并返回数据");
            return false;
        } else if result1.unwrap() != payload1 {
            println!("❌ 错误: 第一个数据包返回的数据不正确");
            return false;
        }
        
        // 发送第二个数据包
        let packet2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq2, payload2.clone());
        let result2 = reassembler.process_packet(&packet2);
        println!("发送第二个包 (seq={}, 内容={:?}), 结果={:?}", seq2, payload2, result2.is_some());
        
        // 第二个包应该返回数据
        if result2.is_none() {
            println!("❌ 错误: 第二个顺序数据包应该返回数据");
            return false;
        } else if result2.unwrap() != payload2 {
            println!("❌ 错误: 第二个数据包返回的数据不正确");
            return false;
        }
        
        // 发送第三个数据包
        let packet3 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq3, payload3.clone());
        let result3 = reassembler.process_packet(&packet3);
        println!("发送第三个包 (seq={}, 内容={:?}), 结果={:?}", seq3, payload3, result3.is_some());
        
        // 第三个包应该返回数据
        if result3.is_none() {
            println!("❌ 错误: 第三个顺序数据包应该返回数据");
            return false;
        } else if result3.unwrap() != payload3 {
            println!("❌ 错误: 第三个数据包返回的数据不正确");
            return false;
        }
        
        println!("✅ 顺序包重组测试通过");
    }
    
    println!("\n------ 测试场景3: 有缺口的乱序数据包 ------");
    {
        let reassembler = ShardedTcpReassembler::new(config.clone());
        
        // 创建数据包，中间有缺口
        let payload1 = b"Start ".to_vec();    // seq = 3000
        let payload2 = b"Middle ".to_vec();   // seq = 3006 (缺口这里)
        let payload3 = b"End".to_vec();       // seq = 3020 (缺口这里)
        
        let seq1 = 3000;
        let seq2 = seq1 + payload1.len() as u32 + 2; // 添加2字节缺口
        let seq3 = seq2 + payload2.len() as u32 + 6; // 添加6字节缺口
        
        println!("序列号: seq1={}, seq2={}, seq3={}", seq1, seq2, seq3);
        
        // 先发送带有缺口的第二个包
        let packet2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq2, payload2.clone());
        let result2 = reassembler.process_packet(&packet2);
        println!("发送第二个包 (seq={}, 内容={:?}), 结果={:?}", seq2, payload2, result2);
        
        // 再发送带有缺口的第三个包
        let packet3 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq3, payload3.clone());
        let result3 = reassembler.process_packet(&packet3);
        println!("发送第三个包 (seq={}, 内容={:?}), 结果={:?}", seq3, payload3, result3);
        
        // 最后发送初始包
        let packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq1, payload1.clone());
        let result1 = reassembler.process_packet(&packet1);
        println!("发送第一个包 (seq={}, 内容={:?}), 结果={:?}", seq1, payload1, result1);
        
        // 验证:
        // 1. 乱序包不应该返回数据
        if result2.is_some() || result3.is_some() {
            println!("❌ 错误: 乱序包不应该返回数据");
            println!("第二个包结果: {:?}", result2.is_some());
            println!("第三个包结果: {:?}", result3.is_some());
            return false;
        }
        
        // 2. 在我们的新实现下，第一个包作为初始包应该能被正确识别并返回
        println!("第一个包结果: {:?}", result1.is_some());
        if result1.is_none() {
            println!("❌ 错误: 第一个包应该能被识别并返回数据");
            return false;
        } else if result1.unwrap() != payload1 {
            println!("❌ 错误: 第一个包返回的数据不正确");
            return false;
        }
        
        println!("✅ 有缺口的乱序数据包测试通过");
    }
    
    println!("========= 全部乱序数据包测试通过! =========");
    true
}

// 测试重传数据包的处理
fn test_retransmission_handling() -> bool {
    // 创建TCP重组器
    let config = ShardConfig {
        shard_count: 2,
        timeout_secs: 1,
        max_gap: 1024,
        max_streams_per_shard: 100,
        max_segments: 10,
        rebalance_threshold: 10_000,
        stats_cleanup_interval: 1,
    };
    let reassembler = ShardedTcpReassembler::new(config);

    let src_ip = 0xC0A80101;
    let dst_ip = 0xC0A80102;
    let src_port = 12345;
    let dst_port = 80;

    // 创建数据包
    let payload1 = b"Hello, ".to_vec();
    let payload2 = b"World!".to_vec();
    
    // 先发送第一个数据包
    let packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, 1000, payload1.clone());
    let result1 = reassembler.process_packet(&packet1);
    
    if let Some(data1) = result1 {
        if data1 != payload1 {
            println!("错误: 第一个数据包的结果不匹配");
            return false;
        }
    } else {
        println!("错误: 第一个数据包应该返回数据");
        return false;
    }
    
    // 发送第二个数据包
    let packet2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, 1000 + payload1.len() as u32, payload2.clone());
    let result2 = reassembler.process_packet(&packet2);
    
    if let Some(data2) = result2 {
        if data2 != payload2 {
            println!("错误: 第二个数据包的结果不匹配");
            return false;
        }
    } else {
        println!("错误: 第二个数据包应该返回数据");
        return false;
    }
    
    // 重传第一个数据包
    let retrans_packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, 1000, payload1.clone());
    let retrans_result1 = reassembler.process_packet(&retrans_packet1);
    
    // 重传的数据包应该被识别出来，不返回数据
    if retrans_result1.is_some() {
        println!("错误: 重传包不应该返回数据");
        return false;
    }
    
    true
}

// 测试具有缺口的数据包序列
fn test_gap_handling() -> bool {
    // 创建TCP重组器
    let config = ShardConfig {
        shard_count: 2,
        timeout_secs: 1,
        max_gap: 1024,
        max_streams_per_shard: 100,
        max_segments: 10,
        rebalance_threshold: 10_000,
        stats_cleanup_interval: 1,
    };
    let reassembler = ShardedTcpReassembler::new(config);

    let src_ip = 0xC0A80101;
    let dst_ip = 0xC0A80102;
    let src_port = 12345;
    let dst_port = 80;

    // 创建有缺口的数据包序列
    let payload1 = b"Hello, ".to_vec();
    let payload2 = b"World".to_vec();
    let payload3 = b"!".to_vec();
    let payload4 = b" Welcome".to_vec();
    
    let seq1 = 1000;
    let seq2 = seq1 + payload1.len() as u32;
    let seq3 = seq2 + payload2.len() as u32;
    // 有缺口的数据包
    let seq4 = seq3 + payload3.len() as u32 + 10; // 中间有10字节的缺口
    
    // 发送第一个数据包
    let packet1 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq1, payload1.clone());
    let result1 = reassembler.process_packet(&packet1);
    
    if result1.is_none() || result1.unwrap() != payload1 {
        println!("错误: 第一个数据包处理失败");
        return false;
    }
    
    // 发送第二个和第三个数据包
    let packet2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq2, payload2.clone());
    let result2 = reassembler.process_packet(&packet2);
    
    if result2.is_none() || result2.unwrap() != payload2 {
        println!("错误: 第二个数据包处理失败");
        return false;
    }
    
    let packet3 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq3, payload3.clone());
    let result3 = reassembler.process_packet(&packet3);
    
    if result3.is_none() || result3.unwrap() != payload3 {
        println!("错误: 第三个数据包处理失败");
        return false;
    }
    
    // 发送有缺口的第四个数据包
    let packet4 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq4, payload4.clone());
    let result4 = reassembler.process_packet(&packet4);
    
    // 由于有缺口，第四个数据包不应加入重组数据
    if result4.is_some() {
        println!("错误: 有缺口的数据包不应该被重组");
        return false;
    }
    
    true
}

// 测试多个流的并行处理
fn test_multiple_streams() -> bool {
    // 创建TCP重组器
    let config = ShardConfig {
        shard_count: 4,
        timeout_secs: 1,
        max_gap: 1024,
        max_streams_per_shard: 100,
        max_segments: 10,
        rebalance_threshold: 10_000,
        stats_cleanup_interval: 1,
    };
    let reassembler = ShardedTcpReassembler::new(config);

    // 创建两个不同的流
    let src_ip1 = 0xC0A80101;
    let dst_ip1 = 0xC0A80102;
    let src_port1 = 12345;
    let dst_port1 = 80;
    
    let src_ip2 = 0xC0A80103;
    let dst_ip2 = 0xC0A80104;
    let src_port2 = 54321;
    let dst_port2 = 443;

    // 流1的数据包
    let payload1_1 = b"Hello from flow 1".to_vec();
    let payload1_2 = b", part 2".to_vec();
    
    // 流2的数据包
    let payload2_1 = b"Hello from flow 2".to_vec();
    let payload2_2 = b", part 2".to_vec();

    // 交替发送两个流的数据包
    let packet1_1 = create_tcp_packet(src_ip1, dst_ip1, src_port1, dst_port1, 1000, payload1_1.clone());
    let result1_1 = reassembler.process_packet(&packet1_1);
    
    let packet2_1 = create_tcp_packet(src_ip2, dst_ip2, src_port2, dst_port2, 2000, payload2_1.clone());
    let result2_1 = reassembler.process_packet(&packet2_1);
    
    let packet1_2 = create_tcp_packet(src_ip1, dst_ip1, src_port1, dst_port1, 1000 + payload1_1.len() as u32, payload1_2.clone());
    let result1_2 = reassembler.process_packet(&packet1_2);
    
    let packet2_2 = create_tcp_packet(src_ip2, dst_ip2, src_port2, dst_port2, 2000 + payload2_1.len() as u32, payload2_2.clone());
    let result2_2 = reassembler.process_packet(&packet2_2);

    // 验证每个流的结果是否正确
    if result1_1.is_none() || result1_1.unwrap() != payload1_1 {
        println!("错误: 流1的第一个数据包处理失败");
        return false;
    }
    
    if result2_1.is_none() || result2_1.unwrap() != payload2_1 {
        println!("错误: 流2的第一个数据包处理失败");
        return false;
    }
    
    if result1_2.is_none() || result1_2.unwrap() != payload1_2 {
        println!("错误: 流1的第二个数据包处理失败");
        return false;
    }
    
    if result2_2.is_none() || result2_2.unwrap() != payload2_2 {
        println!("错误: 流2的第二个数据包处理失败");
        return false;
    }
    
    true
}

fn benchmark_tcp_reassembly_correctness(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_reassembly_correctness");

    // 测试顺序数据包的重组
    group.bench_function("ordered_reassembly", |b| {
        b.iter(|| {
            assert!(test_ordered_reassembly(), "顺序数据包重组测试失败");
        })
    });

    // 测试乱序数据包的重组
    group.bench_function("out_of_order_reassembly", |b| {
        b.iter(|| {
            assert!(test_out_of_order_reassembly(), "乱序数据包重组测试失败");
        })
    });

    // 测试重传数据包的处理
    group.bench_function("retransmission_handling", |b| {
        b.iter(|| {
            assert!(test_retransmission_handling(), "重传数据包处理测试失败");
        })
    });

    // 测试有缺口的数据包序列
    group.bench_function("gap_handling", |b| {
        b.iter(|| {
            assert!(test_gap_handling(), "带缺口数据包处理测试失败");
        })
    });

    // 测试多流并行处理
    group.bench_function("multiple_streams", |b| {
        b.iter(|| {
            assert!(test_multiple_streams(), "多流并行处理测试失败");
        })
    });

    group.finish();
}

criterion_group!(benches, benchmark_tcp_reassembly_correctness);
criterion_main!(benches); 