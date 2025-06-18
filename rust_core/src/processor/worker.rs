use crate::SafePacket;
use crate::decode::{decode_packet, TransportProtocol, DecodedPacket, DecodeContext};
use crate::stream::ShardedTcpReassembler;
use crate::defrag::IpDefragmenter;
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use log::{debug, error, warn, trace};
use std::sync::atomic::{AtomicBool, Ordering};
use num_cpus;

/// 工作线程任务
#[derive(Debug)]
enum Task {
    Process(SafePacket),
    Shutdown,
}

/// 单个工作线程
struct Worker {
    id: usize,
    sender: mpsc::Sender<Task>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Worker {
    fn new(id: usize, receiver: mpsc::Receiver<Task>, reassembler: Arc<ShardedTcpReassembler>, defragmenter: Arc<tokio::sync::RwLock<IpDefragmenter>>) -> Self {
        let (sender, mut task_receiver) = mpsc::channel::<Task>(100);
        
        let handle = std::thread::spawn(move || {
            debug!("Worker {} 启动", id);
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    error!("Worker {} 启动tokio runtime失败: {}", id, e);
                    return;
                }
            };
            rt.block_on(async {
                while let Some(task) = task_receiver.recv().await {
                    match task {
                        Task::Process(packet) => {
                            if let Err(e) = Self::process_packet(&packet, &reassembler, &defragmenter).await {
                                error!("Worker {} 处理数据包失败: {:#}", id, e);
                            }
                        },
                        Task::Shutdown => {
                            debug!("Worker {} 收到关闭信号", id);
                            break;
                        }
                    }
                }
            });
            debug!("Worker {} 退出", id);
        });
        
        Self {
            id,
            sender,
            handle: Some(handle),
        }
    }
    
    async fn process_packet(packet: &SafePacket, reassembler: &Arc<ShardedTcpReassembler>, defragmenter: &Arc<tokio::sync::RwLock<IpDefragmenter>>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 解码数据包
        let mut ctx = DecodeContext::new();
        match decode_packet(&mut ctx, packet, &packet.data[..]) {
            Ok(decoded) => {
                debug!("Worker 解码数据包成功");
                
                // 检查是否为分片包
                if decoded.ip_header.flags & 0x20 != 0 || decoded.ip_header.fragment_offset != 0 {
                    debug!("检测到IP分片包，开始分片重组");
                    
                    let defrag_result = {
                        let mut defrag = defragmenter.write().await;
                        defrag.process_packet(&decoded)
                    };
                    
                    if let Ok(Some(reassembled)) = defrag_result {
                        debug!("IP分片重组完成，处理重组后的数据包");
                        // 处理重组后的数据包
                        match &reassembled.protocol {
                            TransportProtocol::TCP { .. } => {
                                let stream_result = reassembler.process_packet(&reassembled);
                                match stream_result {
                                    Ok(Some(reassembled_data)) => {
                                        debug!("TCP流重组完成，数据长度: {}", reassembled_data.len());
                                        // 这里可以添加应用层处理逻辑
                                    },
                                    Ok(None) => {
                                        trace!("TCP流重组未完成，等待更多数据");
                                    },
                                    Err(e) => {
                                        error!("TCP流重组失败: {:?}", e);
                                    }
                                }
                            },
                            _ => {
                                debug!("非TCP协议，跳过流重组");
                            }
                        }
                    } else if let Err(e) = defrag_result {
                        error!("IP分片重组失败: {:?}", e);
                    }
                } else {
                    // 非分片包，直接处理TCP流
                    Self::process_tcp_stream(&decoded, reassembler)?;
                }
            },
            Err(e) => {
                error!("Worker 解码数据包失败: {:?}", e);
                return Err(Box::new(e));
            }
        }
        
        Ok(())
    }
    
    fn process_tcp_stream(decoded: &DecodedPacket, reassembler: &Arc<ShardedTcpReassembler>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match &decoded.protocol {
            TransportProtocol::TCP { src_port, dst_port, seq, ack, flags, window, payload } => {
                debug!("Worker 检测到TCP包，开始TCP流重组");
                
                // 创建流键
                let stream_key = if *src_port < *dst_port {
                    format!("{}:{}:{}:{}", 
                        decoded.ip_header.source_ip, *src_port,
                        decoded.ip_header.dest_ip, *dst_port)
                } else {
                    format!("{}:{}:{}:{}", 
                        decoded.ip_header.dest_ip, *dst_port,
                        decoded.ip_header.source_ip, *src_port)
                };
                
                debug!("TCP流键: {}", stream_key);
                
                // 处理TCP流重组
                match reassembler.process_packet(decoded) {
                    Ok(Some(reassembled_data)) => {
                        debug!("TCP流重组成功，数据长度: {}", reassembled_data.len());
                        // 这里可以添加应用层处理逻辑
                    },
                    Ok(None) => {
                        debug!("TCP流重组未完成，等待更多数据包");
                    },
                    Err(e) => {
                        error!("TCP流重组失败: {:?}", e);
                    }
                }
            },
            TransportProtocol::UDP { .. } => {
                debug!("Worker 检测到UDP包，跳过流重组");
            }
        }
        
        Ok(())
    }
}

/// 工作线程池
pub struct WorkerPool {
    workers: Vec<Worker>,
    next_worker: Mutex<usize>,
    reassembler: Arc<ShardedTcpReassembler>,
    defragmenter: Arc<tokio::sync::RwLock<IpDefragmenter>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl WorkerPool {
    pub fn new(reassembler: Arc<ShardedTcpReassembler>) -> Self {
        let num_workers = num_cpus::get();
        let mut workers = Vec::with_capacity(num_workers);
        
        let defragmenter = Arc::new(tokio::sync::RwLock::new(IpDefragmenter::new()));
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        for i in 0..num_workers {
            let (sender, receiver) = mpsc::channel::<Task>(100);
            let worker = Worker::new(i, receiver, reassembler.clone(), defragmenter.clone());
            workers.push(worker);
        }
        
        Self {
            workers,
            next_worker: Mutex::new(0),
            reassembler,
            defragmenter,
            shutdown_flag,
        }
    }
    
    /// 提交数据包到工作线程池
    pub async fn submit(&self, packet: SafePacket) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.shutdown_flag.load(Ordering::Relaxed) {
            return Err("WorkerPool已关闭".into());
        }
        
        let worker_index = {
            let mut next = self.next_worker.lock().unwrap();
            let index = *next;
            *next = (*next + 1) % self.workers.len();
            index
        };
        
        let worker = &self.workers[worker_index];
        worker.sender.send(Task::Process(packet)).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        
        Ok(())
    }
    
    /// 关闭工作线程池
    pub async fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.shutdown_flag.load(Ordering::Relaxed) {
            return Ok(());
        }
        
        self.shutdown_flag.store(true, Ordering::Relaxed);
        
        // 发送关闭信号给所有工作线程
        for worker in &self.workers {
            if let Err(e) = worker.sender.send(Task::Shutdown).await {
                warn!("发送关闭信号到Worker {} 失败: {:?}", worker.id, e);
            }
        }
        
        // 等待所有工作线程完成
        for worker in &mut self.workers {
            if let Some(handle) = worker.handle.take() {
                if let Err(e) = handle.join() {
                    error!("Worker {} 关闭时出错: {:?}", worker.id, e);
                }
            }
        }
        
        debug!("WorkerPool 已关闭");
        Ok(())
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        if !self.shutdown_flag.load(Ordering::Relaxed) {
            // 如果还没有关闭，尝试关闭
            // 注意：在Drop中不能使用block_on，因为可能已经在异步上下文中
            // 我们只能发送关闭信号，但不能等待完成
            self.shutdown_flag.store(true, Ordering::Relaxed);
            
            // 发送关闭信号给所有工作线程
            for worker in &self.workers {
                let _ = worker.sender.try_send(Task::Shutdown);
            }
            
            // 等待一小段时间让工作线程有机会退出
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
} 