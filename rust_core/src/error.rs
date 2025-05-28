use std::result::Result as StdResult;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("空指针错误")]
    NullPointer,
    
    #[error("数据包解码失败")]
    DecodeError,
    
    #[error("处理错误: {0}")]
    ProcessError(String),
    
    #[error("流处理错误: {0}")]
    StreamError(String),
    
    #[error("IO错误: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum ReassembleError {
    #[error("解码错误: {0}")]
    DecodeError(String),
    
    #[error("分片重组错误: {0}")]
    DefragError(String),
    
    #[error("流重组错误: {0}")]
    StreamError(String),
    
    #[error(transparent)]
    PacketError(#[from] PacketError),
    
    #[error("系统IO错误: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = StdResult<T, ReassembleError>;