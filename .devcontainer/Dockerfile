# 使用 Debian slim 作为基础镜像
FROM debian:bullseye-slim

# 避免交互式提示
ENV DEBIAN_FRONTEND=noninteractive

# 安装最小依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpcap-dev \
    pkg-config \
    build-essential \
    tcpdump \
    net-tools \
    iproute2 \
    curl \
    gcc \
    libc6-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /workspaces/reassamble

# 安装 Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y && \
    . "$HOME/.cargo/env" && \
    rustup component add rustfmt clippy && \
    cargo install cargo-edit cargo-watch

# 配置环境变量 
ENV PATH="/root/.cargo/bin:${PATH}"
