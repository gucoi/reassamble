#ifndef PCAP_BACKEND_H
#define PCAP_BACKEND_H

#include "capture_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * libpcap 后端特定配置
 */
typedef struct {
    int buffer_size;          // 缓冲区大小
    int timeout_ms;           // 超时时间
    bool immediate;           // 是否立即返回
    bool promiscuous;         // 是否开启混杂模式
    int snaplen;             // 抓包长度
    const char* filter;       // BPF 过滤器
    const char* device;       // 设备名称
} pcap_backend_config_t;

/**
 * 创建 libpcap 后端
 * @param config 配置信息
 * @param error_cb 错误回调函数
 * @param error_user_data 错误回调用户数据
 * @return 成功返回后端结构，失败返回 NULL
 */
capture_backend_t* pcap_backend_create(
    const pcap_backend_config_t* config,
    error_callback_t error_cb,
    void* error_user_data
);

/**
 * 销毁 libpcap 后端
 * @param backend 后端结构
 */
void pcap_backend_destroy(capture_backend_t* backend);

/**
 * 获取 libpcap 版本信息
 * @return 版本字符串
 */
const char* pcap_backend_get_version(void);

/**
 * 检查 libpcap 是否支持特定功能
 * @param feature 功能名称
 * @return 支持返回 true，否则返回 false
 */
bool pcap_backend_is_feature_supported(const char* feature);

/**
 * 设置 libpcap 特定选项
 * @param backend 后端结构
 * @param option 选项名称
 * @param value 选项值
 * @return 成功返回 0，失败返回错误码
 */
int pcap_backend_set_option(
    capture_backend_t* backend,
    const char* option,
    const void* value
);

/**
 * 获取 libpcap 特定选项
 * @param backend 后端结构
 * @param option 选项名称
 * @param value 选项值
 * @return 成功返回 0，失败返回错误码
 */
int pcap_backend_get_option(
    capture_backend_t* backend,
    const char* option,
    void* value
);

/**
 * 初始化 libpcap 后端
 */
capture_handle_t* pcap_backend_init(
    const capture_config_t* config,
    packet_callback_t packet_cb,
    error_callback_t error_cb,
    void* user_data,
    void* error_user_data
);

/**
 * 启动抓包
 */
int pcap_backend_start(capture_handle_t* handle);

/**
 * 停止抓包
 */
int pcap_backend_stop(capture_handle_t* handle);

/**
 * 清理资源
 */
void pcap_backend_cleanup(capture_handle_t* handle);

/**
 * 获取统计信息
 */
int pcap_backend_get_stats(capture_handle_t* handle, capture_stats_t* stats);

#ifdef __cplusplus
}
#endif

#endif // PCAP_BACKEND_H 