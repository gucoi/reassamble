pub mod config;
pub mod decode;
pub mod reassemble;
pub mod applyer;

use std::ffi::c_void;

#[repr(C)]
pub struct Packet {
    data: *const u8,
    len: usize,
    timestamp: u64,
}

#[no_mangle]
pub extern "C" fn process_packet(packet: *const Packet) {
    // 安全性检查
    if packet.is_null() {
        return;
    }
    
    unsafe {
        let packet = &*packet;
        // 1. 解码
        if let Some(decoded) = decode::decode_packet(packet) {
            // 2. 重组
            if let Some(reassembled) = reassemble::reassemble_packet(decoded) {
                // 3. 应用处理
                applyer::apply(reassembled);
            }
        }
    }
}
