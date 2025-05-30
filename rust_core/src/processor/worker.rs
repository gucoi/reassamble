use std::sync::Arc;
use crossbeam_channel::{bounded, Sender, Receiver};
use parking_lot::Mutex;
use std::thread;
use std::collections::HashMap;
use crate::SafePacket;
use crate::memory::get_global_pool;
use num_cpus;
use log::{info, warn};
use bytes::{Bytes, BytesMut, BufMut};

pub struct WorkerPool {
    workers: Vec<Worker>,
    task_senders: Vec<Sender<Task>>,
    next_worker: Mutex<usize>,
}

struct Worker {
    handle: Option<thread::JoinHandle<()>>,
}

#[derive(Clone)]
struct Task {
    packet: SafePacket,
}

impl WorkerPool {
    pub fn new() -> Self {
        let num_workers = num_cpus::get();
        let mut workers = Vec::with_capacity(num_workers);
        let mut task_senders = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let (tx, rx) = bounded::<Task>(1000);
            task_senders.push(tx);
            
            let worker = Worker::new(rx);
            workers.push(worker);
        }

        Self {
            workers,
            task_senders,
            next_worker: Mutex::new(0),
        }
    }

    pub fn submit(&self, packet: SafePacket) {
        let mut next = self.next_worker.lock();
        let worker_id = *next;
        *next = (worker_id + 1) % self.task_senders.len();

        if let Err(e) = self.task_senders[worker_id].send(Task {
            packet,
        }) {
            warn!("Failed to submit task to worker {}: {}", worker_id, e);
        }
    }

    pub fn shutdown(&mut self) {
        for worker in &mut self.workers {
            if let Some(handle) = worker.handle.take() {
                if let Err(e) = handle.join() {
                    warn!("Error joining worker thread: {:?}", e);
                }
            }
        }
    }
}

impl Worker {
    fn new(rx: Receiver<Task>) -> Self {
        let handle = thread::spawn(move || {
            let pool = get_global_pool();
            
            while let Ok(task) = rx.recv() {
                let packet = task.packet;
                // 获取合适的内存池
                if let Some(pool_arc) = crate::memory::get_pool(packet.data.len()) {
                    let mut pool = pool_arc.lock();
                    if let Some(mut block) = pool.acquire(packet.data.len()) {
                        block.extend_from_slice(&packet.data);
                        let _processed_data = block.freeze();
                        pool.release(block);
                    }
                }
            }
        });

        Self {
            handle: Some(handle),
        }
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        self.shutdown();
    }
} 