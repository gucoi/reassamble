use std::os::raw::{c_char, c_void};
use super::types::{CaptureConfig, CaptureHandle, CaptureCallback, ErrorCallback, CaptureDevice, CaptureStats};

#[link(name = "capture")]
extern "C" {
    pub fn capture_init(
        config: *const CaptureConfig,
        error_cb: ErrorCallback,
        error_user_data: *mut c_void,
    ) -> *mut CaptureHandle;

    pub fn capture_start(
        handle: *mut CaptureHandle,
        packet_cb: CaptureCallback,
        user_data: *mut c_void,
    ) -> i32;

    pub fn capture_stop(handle: *mut CaptureHandle) -> i32;
    pub fn capture_cleanup(handle: *mut CaptureHandle);
    pub fn capture_set_filter(handle: *mut CaptureHandle, filter: *const c_char) -> i32;
    pub fn capture_get_stats(handle: *mut CaptureHandle, stats: *mut CaptureStats) -> i32;
    
    // 添加缺失的函数
    pub fn capture_pause(handle: *mut CaptureHandle) -> i32;
    pub fn capture_resume(handle: *mut CaptureHandle) -> i32;
    pub fn capture_get_devices(devices: *mut *mut CaptureDevice, count: *mut i32) -> i32;
    pub fn capture_free_devices(devices: *mut CaptureDevice, count: i32);
}

// 添加安全的 Rust 包装函数
pub fn init_capture(
    config: &CaptureConfig,
    error_cb: ErrorCallback,
    error_user_data: *mut c_void,
) -> Option<*mut CaptureHandle> {
    let handle = unsafe { capture_init(config, error_cb, error_user_data) };
    if handle.is_null() {
        None
    } else {
        Some(handle)
    }
}

pub fn start_capture(
    handle: *mut CaptureHandle,
    packet_cb: CaptureCallback,
    user_data: *mut c_void,
) -> Result<(), i32> {
    let result = unsafe { capture_start(handle, packet_cb, user_data) };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

pub fn stop_capture(handle: *mut CaptureHandle) -> Result<(), i32> {
    let result = unsafe { capture_stop(handle) };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

pub fn set_capture_filter(handle: *mut CaptureHandle, filter: &str) -> Result<(), i32> {
    let c_filter = std::ffi::CString::new(filter).unwrap();
    let result = unsafe { capture_set_filter(handle, c_filter.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

pub fn get_capture_stats(handle: *mut CaptureHandle) -> Result<CaptureStats, i32> {
    let mut stats = CaptureStats::default();
    let result = unsafe { capture_get_stats(handle, &mut stats) };
    if result == 0 {
        Ok(stats)
    } else {
        Err(result)
    }
}

pub fn pause_capture(handle: *mut CaptureHandle) -> Result<(), i32> {
    let result = unsafe { capture_pause(handle) };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

pub fn resume_capture(handle: *mut CaptureHandle) -> Result<(), i32> {
    let result = unsafe { capture_resume(handle) };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

pub fn get_capture_devices() -> Result<Vec<CaptureDevice>, i32> {
    let mut devices: *mut CaptureDevice = std::ptr::null_mut();
    let mut count: i32 = 0;
    
    let result = unsafe { capture_get_devices(&mut devices, &mut count) };
    if result != 0 {
        return Err(result);
    }
    
    let mut device_vec = Vec::with_capacity(count as usize);
    unsafe {
        for i in 0..count {
            device_vec.push(std::ptr::read(devices.add(i as usize)));
        }
        capture_free_devices(devices, count);
    }
    
    Ok(device_vec)
} 