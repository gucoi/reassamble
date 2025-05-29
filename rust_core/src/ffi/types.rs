use std::os::raw::{c_char, c_void};
use libc::timespec;

#[repr(C)]
pub struct CapturePacket {
    pub data: *const u8,
    pub len: u32,
    pub caplen: u32,
    pub ts: timespec,
    pub if_index: u32,
    pub flags: u32,
    pub protocol: u32,
    pub vlan_tci: u32,
    pub hash: u32,
}

#[repr(C)]
pub struct ReassemblePacket {
    pub data: *const u8,
    pub len: usize,
    pub timestamp: u64,
}

// 回调函数类型
pub type CaptureCallback = extern "C" fn(packet: *const CapturePacket, user_data: *mut c_void) -> bool;
pub type ErrorCallback = extern "C" fn(error: *const c_char, user_data: *mut c_void);

// 配置结构
#[repr(C)]
pub struct CaptureConfig {
    pub device: *const c_char,
    pub filter: *const c_char,
    pub snaplen: i32,
    pub timeout_ms: i32,
    pub promiscuous: bool,
    pub immediate: bool,
    pub buffer_size: u32,
    pub backend_type: CaptureBackendType,
}

// 后端类型
#[repr(C)]
pub enum CaptureBackendType {
    Pcap = 0,
    Pfring = 1,
    Dpdk = 2,
    Ebpf = 3,
}

// 句柄类型
#[repr(C)]
pub struct CaptureHandle {
    _private: [u8; 0],
} 