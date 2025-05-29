#ifndef CAPTURE_BACKEND_H
#define CAPTURE_BACKEND_H

#include "../capture_types.h"
#include "../capture.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 后端操作函数表
 */
typedef struct {
    // 初始化后端
    int (*init)(void* backend, const capture_config_t* config);
    
    // 清理后端
    void (*cleanup)(void* backend);
    
    // 打开设备
    int (*open)(void* backend, const char* device);
    
    // 关闭设备
    int (*close)(void* backend);
    
    // 开始抓包
    int (*start)(void* backend, packet_callback_t callback, void* user_data);
    
    // 停止抓包
    int (*stop)(void* backend);
    
    // 暂停抓包
    int (*pause)(void* backend);
    
    // 恢复抓包
    int (*resume)(void* backend);
    
    // 设置过滤器
    int (*set_filter)(void* backend, const char* filter);
    
    // 获取统计信息
    int (*get_stats)(void* backend, capture_stats_t* stats);
    
    // 获取设备列表
    int (*get_devices)(void* backend, capture_device_t** devices, int* count);
    
    // 释放设备列表
    void (*free_devices)(void* backend, capture_device_t* devices, int count);
    
    // 获取后端名称
    const char* (*get_name)(void* backend);
    
    // 获取后端版本
    const char* (*get_version)(void* backend);
    
    // 获取后端描述
    const char* (*get_description)(void* backend);
    
    // 检查后端是否支持特定功能
    bool (*is_feature_supported)(void* backend, const char* feature);
    
    // 设置后端特定选项
    int (*set_option)(void* backend, const char* option, const void* value);
    
    // 获取后端特定选项
    int (*get_option)(void* backend, const char* option, void* value);
} capture_backend_ops_t;

/**
 * 后端结构
 */
typedef struct {
    void* private_data;              // 后端私有数据
    capture_backend_ops_t* ops;      // 操作函数表
    capture_backend_type_t type;     // 后端类型
    error_callback_t error_cb;       // 错误回调
    void* error_user_data;          // 错误回调用户数据
} capture_backend_t;

/**
 * 注册后端
 * @param backend 后端结构
 * @return 成功返回 0，失败返回错误码
 */
int capture_backend_register(capture_backend_t* backend);

/**
 * 注销后端
 * @param type 后端类型
 * @return 成功返回 0，失败返回错误码
 */
int capture_backend_unregister(capture_backend_type_t type);

/**
 * 获取后端
 * @param type 后端类型
 * @return 成功返回后端结构，失败返回 NULL
 */
capture_backend_t* capture_backend_get(capture_backend_type_t type);

/**
 * 获取所有已注册的后端
 * @param backends 后端列表
 * @param count 后端数量
 * @return 成功返回 0，失败返回错误码
 */
int capture_backend_get_all(capture_backend_t** backends, int* count);

/**
 * 释放后端列表
 * @param backends 后端列表
 * @param count 后端数量
 */
void capture_backend_free_all(capture_backend_t* backends, int count);

#ifdef __cplusplus
}
#endif

#endif // CAPTURE_BACKEND_H 