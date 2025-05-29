use std::os::raw::{c_char, c_void};
use super::types::{CaptureConfig, CaptureHandle, CaptureCallback, ErrorCallback};

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
    pub fn capture_get_stats(handle: *mut CaptureHandle, stats: *mut c_void) -> i32;
} 