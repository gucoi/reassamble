FROM ubuntu:22.04

# 避免交互式提示
ENV DEBIAN_FRONTEND=noninteractive

# 安装基础工具和C开发环境
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    gdb \
    clang \
    make \
    pkg-config \
    git \
    curl \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# 安装 Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# 安装常用的 Rust 组件
RUN rustup component add \
    rustfmt \
    clippy \
    rust-src \
    rust-analyzer
