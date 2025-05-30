use super::types::ReassemblePacket;
use crate::error::Result;
use bytes;

#[no_mangle]
pub extern "C" fn process_reassemble_packet(packet: *const ReassemblePacket) -> Result<()> {
    if packet.is_null() || unsafe { (*packet).data.is_null() } {
        return Err(crate::error::ReassembleError::PacketError(
            crate::error::PacketError::NullPointer,
        ));
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

        if let Some(data) = result {
            println!("Reassembled {} bytes", data.len());
        }
        
        Ok(())
    })
} 