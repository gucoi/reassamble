# Reassamble

一个高性能的网络数据包重组和分析工具，使用 Rust 和 C 语言实现。

## 功能特点

- 支持多种抓包后端（libpcap、PF_RING、DPDK、eBPF）
- 高性能的 IP 分片重组
  - 支持乱序包处理
  - 自动分片排序
  - 分片超时检测
  - 分片组完整性检查
- TCP 流重组和会话跟踪
- 异步处理架构
- 完整的错误处理
- 详细的统计信息

## 系统要求

- Rust 1.70 或更高版本
- Cargo
- CMake 3.10 或更高版本
- libpcap 开发库
- Clang（用于生成 Rust 绑定）
- Linux 系统（推荐 Ubuntu 20.04 或更高版本）

## 安装依赖

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    clang \
    libpcap-dev \
    pkg-config
```

### CentOS/RHEL

```bash
sudo yum groupinstall "Development Tools"
sudo yum install cmake clang libpcap-devel
```

## 构建项目

```bash
# 克隆仓库
git clone https://github.com/yourusername/reassamble.git
cd reassamble

# 编译 c_capture 模块
cd c_capture
mkdir -p build
cd build
cmake ..
make
cd ../..

# 构建 Rust 项目
cd rust_core
cargo build --release
```

## 项目结构

```
.
├── c_capture/           # C 语言实现的抓包模块
│   ├── include/        # 头文件
│   ├── src/           # 源代码
│   └── build/         # 编译输出目录
├── rust_core/         # Rust 核心实现
│   ├── src/          # 源代码
│   └── tests/        # 测试代码
└── README.md
```

## 使用示例

```rust
use rust_core::capture::{CaptureConfig, CaptureBackendType};
use std::ffi::CString;

fn main() {
    // 创建配置
    let device = CString::new("eth0").unwrap();
    let filter = CString::new("tcp").unwrap();
    
    let config = CaptureConfig {
        device: device.as_ptr(),
        filter: filter.as_ptr(),
        snaplen: 65535,
        timeout_ms: 1000,
        promiscuous: true,
        immediate: true,
        buffer_size: 1024 * 1024,
        backend_type: CaptureBackendType::Pcap,
    };

    // 初始化抓包
    let handle = unsafe { capture_init(&config, error_callback, std::ptr::null_mut()) };
    
    // 启动抓包
    unsafe { capture_start(handle, packet_callback, std::ptr::null_mut()) };
    
    // ... 处理数据包 ...
    
    // 停止抓包
    unsafe { capture_stop(handle) };
    
    // 清理资源
    unsafe { capture_cleanup(handle) };
}
```

## 乱序包处理

系统能够处理乱序到达的 IP 分片包：

1. 分片存储
   - 使用哈希表存储分片组
   - 每个分片组包含多个分片
   - 分片按偏移量自动排序

2. 重组机制
   - 检查分片连续性
   - 验证分片完整性
   - 处理分片超时
   - 支持分片组整体超时

3. 性能优化
   - 异步处理架构
   - 定期清理过期分片
   - 内存使用优化

## 测试

运行单元测试：
```bash
cargo test
```

运行集成测试：
```bash
cargo test --test integration_test
```

## 性能测试

运行基准测试：
```bash
cargo bench
```

## 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 联系方式

- 项目维护者：[Your Name]
- 邮箱：[your.email@example.com]
- 项目链接：[https://github.com/yourusername/reassamble]
