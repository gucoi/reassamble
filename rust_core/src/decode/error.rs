use thiserror::Error;
use std::net::IpAddr;

/// 解码错误类型
#[derive(Debug, Error)]
pub enum DecodeError {
    /// 数据包为空
    #[error("空数据包")]
    EmptyPacket,

    /// 数据包长度不足
    #[error("数据包长度不足: 需要 {required} 字节，实际 {actual} 字节")]
    InsufficientLength {
        required: usize,
        actual: usize,
    },

    /// IP头部错误
    #[error("IP头部错误: {0}")]
    IpHeaderError(#[from] IpHeaderError),

    /// TCP头部错误
    #[error("TCP头部错误: {0}")]
    TcpHeaderError(#[from] TcpHeaderError),

    /// UDP头部错误
    #[error("UDP头部错误: {0}")]
    UdpHeaderError(#[from] UdpHeaderError),

    /// 不支持的协议
    #[error("不支持的协议: {protocol}")]
    UnsupportedProtocol {
        protocol: u8,
    },

    /// 校验和错误
    #[error("校验和错误: 预期 {expected:04x}, 实际 {actual:04x}")]
    ChecksumError {
        expected: u16,
        actual: u16,
    },

    /// 缓冲区错误
    #[error("缓冲区错误: {0}")]
    BufferError(#[from] BufferError),

    /// 其他错误
    #[error("其他错误: {0}")]
    Other(String),
}

/// IP头部错误类型
#[derive(Debug, Error)]
pub enum IpHeaderError {
    /// 版本错误
    #[error("IP头部长度不足")]
    TooShort,

    /// IHL错误
    #[error("IP版本不支持: {version}")]
    UnsupportedVersion {
        version: u8,
    },

    /// 总长度错误
    #[error("无效的总长度: {length}")]
    InvalidTotalLength {
        length: u16,
    },

    /// 源IP地址错误
    #[error("无效的源IP地址: {ip}")]
    InvalidSourceIp {
        ip: IpAddr,
    },

    /// 目标IP地址错误
    #[error("无效的目标IP地址: {ip}")]
    InvalidDestinationIp {
        ip: IpAddr,
    },

    /// 校验和错误
    #[error("IP头部校验和错误")]
    InvalidChecksum,
}

/// TCP头部错误类型
#[derive(Debug, Error)]
pub enum TcpHeaderError {
    /// 头部长度错误
    #[error("TCP头部长度不足")]
    TooShort,

    /// 头部长度无效
    #[error("无效的TCP头部长度: {length}")]
    InvalidHeaderLength {
        length: u8,
    },

    /// 端口错误
    #[error("无效的端口号: {port}")]
    InvalidPort {
        port: u16,
    },

    /// 序列号错误
    #[error("无效的序列号: {seq}")]
    InvalidSequence {
        seq: u32,
    },

    /// 标志错误
    #[error("无效的TCP标志: {flags:02x}")]
    InvalidFlags {
        flags: u8,
    },

    /// 校验和错误
    #[error("TCP头部校验和错误")]
    InvalidChecksum,
}

/// UDP头部错误类型
#[derive(Debug, Error)]
pub enum UdpHeaderError {
    /// 长度错误
    #[error("UDP头部长度不足")]
    TooShort,

    /// 无效长度
    #[error("无效的UDP长度: {length}")]
    InvalidLength {
        length: u16,
    },

    /// 端口错误
    #[error("无效的端口号: {port}")]
    InvalidPort {
        port: u16,
    },

    /// 校验和错误
    #[error("UDP头部校验和错误")]
    InvalidChecksum,
}

/// 缓冲区错误类型
#[derive(Debug, Error)]
pub enum BufferError {
    /// 缓冲区容量不足
    #[error("缓冲区太短")]
    TooShort,

    /// 缓冲区为空
    #[error("缓冲区为空")]
    EmptyBuffer,

    /// 缓冲区溢出
    #[error("缓冲区溢出")]
    Overflow,
}

impl DecodeError {
    /// 添加上下文信息
    pub fn with_context(self, context: &str) -> Self {
        match self {
            DecodeError::Other(msg) => DecodeError::Other(format!("{}: {}", context, msg)),
            _ => DecodeError::Other(format!("{}: {}", context, self)),
        }
    }

    /// 检查是否为严重错误
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            DecodeError::IpHeaderError(_) | 
            DecodeError::TcpHeaderError(_) | 
            DecodeError::UdpHeaderError(_)
        )
    }
}

/// 结果类型别名
pub type DecodeResult<T> = Result<T, DecodeError>; 