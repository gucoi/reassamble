use super::types::ReassemblePacket;
use crate::error::{ReassembleError, PacketError};
use bytes;

#[repr(C)]
pub enum CResult {
    Ok = 0,
    Err = 1,
}

#[no_mangle]
pub extern "C" fn process_reassemble_packet(packet: *const ReassemblePacket) -> CResult {
    match unsafe { process_reassemble_packet_internal(packet) } {
        Ok(_) => CResult::Ok,
        Err(_) => CResult::Err,
    }
}

unsafe fn process_reassemble_packet_internal(packet: *const ReassemblePacket) -> std::result::Result<(), ReassembleError> {
    if packet.is_null() {
        return Err(ReassembleError::PacketError(PacketError::NullPointer));
    }

    let processor = crate::get_processor();
    let rt = crate::get_runtime();
    
    rt.block_on(async {
        // 先复制数据到安全的 Vec 中
        let packet_data = unsafe { 
            let p = &*packet;
            let slice = std::slice::from_raw_parts(p.data, p.len);
            crate::SafePacket {
                data: bytes::BytesMut::from(slice),
                timestamp: p.timestamp,
            }
        };
        
        // 在工作线程中处理
        let result = processor.process_packet(&packet_data).await?;

        if let Some(data) = result.data {
            println!("Reassembled {} bytes", data.len());
        }
        
        Ok(())
    })
} 