use super::*;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// 测试回调函数
extern "C" fn test_packet_callback(packet: *const CapturePacket, user_data: *mut c_void) -> bool {
    let running = unsafe { &*(user_data as *const AtomicBool) };
    if !running.load(Ordering::Relaxed) {
        return false;
    }

    if packet.is_null() {
        return false;
    }

    let packet = unsafe { &*packet };
    println!("收到数据包: 长度={}, 协议={}", packet.len, packet.protocol);
    true
}

extern "C" fn test_error_callback(error: *const c_char, user_data: *mut c_void) {
    if error.is_null() {
        return;
    }
    let error_str = unsafe { std::ffi::CStr::from_ptr(error) };
    println!("错误: {}", error_str.to_string_lossy());
}

#[test]
fn test_capture_init() {
    let device = CString::new("lo").unwrap();
    let filter = CString::new("").unwrap();
    
    let config = CaptureConfig {
        device: device.as_ptr(),
        filter: filter.as_ptr(),
        snaplen: 65535,
        timeout_ms: 1000,
        promiscuous: false,
        immediate: true,
        buffer_size: 1024 * 1024,
        backend_type: CaptureBackendType::Pcap,
        backend_config: std::ptr::null_mut(),
    };

    let handle = unsafe {
        capture_init(
            &config,
            test_error_callback,
            std::ptr::null_mut(),
        )
    };

    assert!(!handle.is_null());
    unsafe { capture_cleanup(handle) };
}

#[test]
fn test_capture_devices() {
    let mut devices: *mut CaptureDevice = std::ptr::null_mut();
    let mut count: i32 = 0;

    let result = unsafe { capture_get_devices(&mut devices, &mut count) };
    assert_eq!(result, 0);
    assert!(!devices.is_null());
    assert!(count > 0);

    unsafe {
        for i in 0..count {
            let device = &*devices.add(i as usize);
            println!(
                "设备: {}, 描述: {}",
                std::ffi::CStr::from_ptr(device.name.as_ptr()).to_string_lossy(),
                std::ffi::CStr::from_ptr(device.description.as_ptr()).to_string_lossy()
            );
        }
        capture_free_devices(devices, count);
    }
}

#[test]
fn test_capture_start_stop() {
    let device = CString::new("lo").unwrap();
    let filter = CString::new("").unwrap();
    
    let config = CaptureConfig {
        device: device.as_ptr(),
        filter: filter.as_ptr(),
        snaplen: 65535,
        timeout_ms: 1000,
        promiscuous: false,
        immediate: true,
        buffer_size: 1024 * 1024,
        backend_type: CaptureBackendType::Pcap,
        backend_config: std::ptr::null_mut(),
    };

    let handle = unsafe {
        capture_init(
            &config,
            test_error_callback,
            std::ptr::null_mut(),
        )
    };
    assert!(!handle.is_null());

    let running = Arc::new(AtomicBool::new(true));
    let running_ptr = Arc::into_raw(running.clone()) as *mut c_void;

    // 启动捕获
    let result = unsafe {
        capture_start(
            handle,
            test_packet_callback,
            running_ptr,
        )
    };
    assert_eq!(result, 0);

    // 等待一段时间
    std::thread::sleep(std::time::Duration::from_secs(2));

    // 停止捕获
    running.store(false, Ordering::Relaxed);
    let result = unsafe { capture_stop(handle) };
    assert_eq!(result, 0);

    // 清理
    unsafe {
        capture_cleanup(handle);
        let _ = Arc::from_raw(running_ptr as *const AtomicBool);
    }
} 