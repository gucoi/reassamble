use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub capture: CaptureConfig,
    pub decode: DecodeConfig,
    pub reassemble: ReassembleConfig, 
    pub output: OutputConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub interface: String,
    pub bpf_filter: Option<String>,
    pub buffer_size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecodeConfig {
    pub check_checksum: bool,
    pub store_raw: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReassembleConfig {
    pub timeout: u64,
    pub max_segments: usize,
    pub max_packets: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: OutputFormat,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Pcap,
    Csv,
}

impl Config {
    pub fn new() -> Self {
        Config {
            capture: CaptureConfig {
                interface: String::from("any"),
                bpf_filter: None,
                buffer_size: 65536,
            },
            decode: DecodeConfig {
                check_checksum: true,
                store_raw: false,
            },
            reassemble: ReassembleConfig {
                timeout: 30,
                max_segments: 1024,
                max_packets: 65536,
            },
            output: OutputConfig {
                format: OutputFormat::Pcap,
                path: String::from("output.pcap"),
            },
        }
    }
}
