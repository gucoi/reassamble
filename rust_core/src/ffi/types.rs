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

// 设备信息结构
#[repr(C)]
pub struct CaptureDevice {
    pub name: *const c_char,
    pub description: *const c_char,
    pub addresses: *const c_char,
    pub flags: u32,
    pub mtu: u32,
    pub speed: u32,
    pub link_type: u32,
}

// 统计信息结构
#[repr(C)]
pub struct CaptureStats {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub packets_if_dropped: u64,
    pub bytes_received: u64,
    pub bytes_dropped: u64,
    pub bytes_if_dropped: u64,
    pub errors: u64,
    pub warnings: u64,
    pub timestamp: timespec,
}

impl Default for CaptureStats {
    fn default() -> Self {
        Self {
            packets_received: 0,
            packets_dropped: 0,
            packets_if_dropped: 0,
            bytes_received: 0,
            bytes_dropped: 0,
            bytes_if_dropped: 0,
            errors: 0,
            warnings: 0,
            timestamp: timespec { tv_sec: 0, tv_nsec: 0 },
        }
    }
} 