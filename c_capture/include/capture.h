#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>
#include <stdbool.h>
#include "capture_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 抓包后端类型
 */
typedef enum {
    CAPTURE_BACKEND_PCAP,    // libpcap 后端
    CAPTURE_BACKEND_PFRING,  // PF_RING 后端
    CAPTURE_BACKEND_DPDK,    // DPDK 后端
    CAPTURE_BACKEND_EBPF,    // eBPF 后端
} capture_backend_type_t;

/**
 * 抓包配置结构
 */
typedef struct {
    const char* device;           // 网络接口名称
    const char* filter;           // BPF 过滤器
    int snaplen;                  // 抓包长度
    int timeout_ms;               // 超时时间（毫秒）
    bool promiscuous;             // 是否开启混杂模式
    bool immediate;               // 是否立即返回
    uint32_t buffer_size;         // 缓冲区大小
    capture_backend_type_t type;  // 后端类型
    void* backend_config;         // 后端特定配置
} capture_config_t;

/**
 * 抓包句柄
 */
typedef struct capture_handle capture_handle_t;

/**
 * 数据包回调函数类型
 * @param packet 数据包
 * @param user_data 用户数据
 * @return 返回 true 继续抓包，false 停止抓包
 */
typedef bool (*packet_callback_t)(const packet_t* packet, void* user_data);

/**
 * 错误回调函数类型
 * @param error 错误信息
 * @param user_data 用户数据
 */
typedef void (*error_callback_t)(const char* error, void* user_data);

/**
 * 初始化抓包系统
 * @param config 配置信息
 * @param error_cb 错误回调函数
 * @param error_user_data 错误回调用户数据
 * @return 成功返回抓包句柄，失败返回 NULL
 */
capture_handle_t* capture_init(
    const capture_config_t* config,
    error_callback_t error_cb,
    void* error_user_data
);

/**
 * 开始抓包
 * @param handle 抓包句柄
 * @param packet_cb 数据包回调函数
 * @param user_data 用户数据
 * @return 成功返回 0，失败返回错误码
 */
int capture_start(
    capture_handle_t* handle,
    packet_callback_t packet_cb,
    void* user_data
);

/**
 * 停止抓包
 * @param handle 抓包句柄
 * @return 成功返回 0，失败返回错误码
 */
int capture_stop(capture_handle_t* handle);

/**
 * 暂停抓包
 * @param handle 抓包句柄
 * @return 成功返回 0，失败返回错误码
 */
int capture_pause(capture_handle_t* handle);

/**
 * 恢复抓包
 * @param handle 抓包句柄
 * @return 成功返回 0，失败返回错误码
 */
int capture_resume(capture_handle_t* handle);

/**
 * 获取统计信息
 * @param handle 抓包句柄
 * @param stats 统计信息结构
 * @return 成功返回 0，失败返回错误码
 */
int capture_get_stats(capture_handle_t* handle, capture_stats_t* stats);

/**
 * 设置过滤器
 * @param handle 抓包句柄
 * @param filter BPF 过滤器
 * @return 成功返回 0，失败返回错误码
 */
int capture_set_filter(capture_handle_t* handle, const char* filter);

/**
 * 获取支持的设备列表
 * @param devices 设备列表
 * @param count 设备数量
 * @return 成功返回 0，失败返回错误码
 */
int capture_get_devices(capture_device_t** devices, int* count);

/**
 * 释放设备列表
 * @param devices 设备列表
 * @param count 设备数量
 */
void capture_free_devices(capture_device_t* devices, int count);

/**
 * 清理抓包句柄
 * @param handle 抓包句柄
 */
void capture_cleanup(capture_handle_t* handle);

#ifdef __cplusplus
}
#endif

#endif // CAPTURE_H 