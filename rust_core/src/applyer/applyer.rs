use super::reassemble::ReassembledStream;
use std::fs::OpenOptions;
use std::io::Write;

pub fn apply(stream: ReassembledStream) {
    // 示例：将重组后的流保存到文件
    let filename = format!("stream_{}_{}_{}_{}.bin",
        stream.src_ip,
        stream.src_port,
        stream.dst_ip,
        stream.dst_port
    );

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)
    {
        let _ = file.write_all(&stream.data);
    }
}