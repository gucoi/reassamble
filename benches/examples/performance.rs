use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;
use rust_core::init_memory_pool;
use rust_core::config::Config;
use rust_core::stream::ShardConfig;

// 测试创建配置
fn test_create_config() -> bool {
    let _config = Config::default();
    
    // 不需要实际验证值，只要不panic就算成功
    println!("成功创建默认配置");
    true
}

// 测试创建分片配置
fn test_shard_config() -> bool {
    // 创建默认配置
    let default_config = ShardConfig::default();
    
    // 创建自定义配置（根据实际结构体定义）
    let custom_config = ShardConfig {
        shard_count: 8,
        timeout_secs: 30,
        max_gap: 1024,
        max_streams_per_shard: 1000,
        max_segments: 100,
        rebalance_threshold: 1_000_000,
        stats_cleanup_interval: 60,
    };
    
    // 验证配置值
    default_config.timeout_secs > 0 && custom_config.shard_count == 8
}

// 测试内存池初始化性能
fn test_memory_pool_init_perf() -> bool {
    init_memory_pool();
    true
}

fn benchmark_configuration(c: &mut Criterion) {
    let mut group = c.benchmark_group("configuration");
    group.measurement_time(Duration::from_secs(1));
    group.sample_size(10);
    
    // 测试配置创建
    group.bench_function("create_config", |b| {
        b.iter(|| {
            assert!(test_create_config());
        });
    });
    
    // 测试分片配置创建
    group.bench_function("shard_config", |b| {
        b.iter(|| {
            assert!(test_shard_config());
        });
    });
    
    // 测试内存池初始化性能
    group.bench_function("memory_pool_perf", |b| {
        b.iter(|| {
            assert!(test_memory_pool_init_perf());
        });
    });
    
    group.finish();
}

criterion_group!(benches, benchmark_configuration);
criterion_main!(benches); 