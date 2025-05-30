use std::sync::Arc;
use parking_lot::Mutex;
use std::ops::{Deref, DerefMut};
use bytes::{Bytes, BytesMut, BufMut};
use std::sync::atomic::{AtomicBool, Ordering};

/// 内存块结构
#[derive(Debug, Clone)]
pub struct MemoryBlock {
    pub(crate) data: Arc<Mutex<BytesMut>>,
    pub(crate) used: bool,
}

impl MemoryBlock {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Arc::new(Mutex::new(BytesMut::with_capacity(capacity))),
            used: false,
        }
    }

    pub fn with_data(data: impl Into<Bytes>) -> Self {
        let bytes = data.into();
        Self {
            data: Arc::new(Mutex::new(BytesMut::from(&bytes[..]))),
            used: false,
        }
    }

    pub fn capacity(&self) -> usize {
        self.data.lock().capacity()
    }

    pub fn is_used(&self) -> bool {
        self.used
    }

    pub fn mark_used(&mut self) {
        self.used = true;
    }

    pub fn mark_free(&mut self) {
        self.used = false;
        self.data.lock().clear();
    }

    pub fn mark_unused(&mut self) {
        self.mark_free();
    }

    pub fn clear(&mut self) {
        self.data.lock().clear();
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.data.lock().extend_from_slice(data);
    }

    pub fn freeze(&self) -> Bytes {
        self.data.lock().clone().freeze()
    }

    pub fn len(&self) -> usize {
        self.data.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.lock().is_empty()
    }

    pub fn size(&self) -> usize {
        self.data.lock().capacity()
    }

    pub fn lock(&self) -> parking_lot::MutexGuard<BytesMut> {
        self.data.lock()
    }
}

impl Default for MemoryBlock {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl PartialEq for MemoryBlock {
    fn eq(&self, other: &Self) -> bool {
        let self_data = self.data.lock();
        let other_data = other.data.lock();
        self_data.as_ref() == other_data.as_ref() && self.used == other.used
    }
} 