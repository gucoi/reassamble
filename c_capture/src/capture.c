#include "capture.h"
#include "backends/pcap_backend.h"
#include <stdlib.h>
#include <string.h>
#include "capture_types.h"
#include "backends/capture_backend.h"

// 抓包句柄结构
struct capture_handle {
    capture_backend_t* backend;  // 后端实例
    bool is_running;            // 是否正在运行
    bool is_paused;            // 是否暂停
    capture_stats_t stats;     // 统计信息
};

capture_handle_t* capture_init(
    const capture_config_t* config,
    error_callback_t error_cb,
    void* error_user_data
) {
    if (!config || !error_cb) {
        return NULL;
    }

    // 创建句柄
    capture_handle_t* handle = (capture_handle_t*)calloc(1, sizeof(capture_handle_t));
    if (!handle) {
        return NULL;
    }

    // 根据配置创建后端
    switch (config->type) {
        case CAPTURE_BACKEND_PCAP: {
            pcap_backend_config_t pcap_config = {
                .buffer_size = config->buffer_size,
                .timeout_ms = config->timeout_ms,
                .immediate = config->immediate,
                .promiscuous = config->promiscuous,
                .snaplen = config->snaplen,
                .filter = config->filter,
                .device = config->device
            };
            handle->backend = pcap_backend_create(&pcap_config, error_cb, error_user_data);
            break;
        }
        // TODO: 添加其他后端的支持
        default:
            error_cb("Unsupported backend type", error_user_data);
            free(handle);
            return NULL;
    }

    if (!handle->backend) {
        free(handle);
        return NULL;
    }

    handle->is_running = false;
    handle->is_paused = false;
    memset(&handle->stats, 0, sizeof(capture_stats_t));

    return handle;
}

int capture_start(
    capture_handle_t* handle,
    packet_callback_t packet_cb,
    void* user_data
) {
    if (!handle || !handle->backend || !packet_cb) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    if (handle->is_running) {
        return CAPTURE_SUCCESS;
    }

    // 调用后端的启动函数
    int ret = handle->backend->ops->start(handle->backend, packet_cb, user_data);
    if (ret == 0) {
        handle->is_running = true;
        handle->is_paused = false;
    }

    return ret;
}

int capture_stop(capture_handle_t* handle) {
    if (!handle || !handle->backend) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    if (!handle->is_running) {
        return CAPTURE_SUCCESS;
    }

    // 调用后端的停止函数
    int ret = handle->backend->ops->stop(handle->backend);
    if (ret == 0) {
        handle->is_running = false;
        handle->is_paused = false;
    }

    return ret;
}

int capture_pause(capture_handle_t* handle) {
    if (!handle || !handle->backend) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    if (!handle->is_running || handle->is_paused) {
        return CAPTURE_SUCCESS;
    }

    // 调用后端的暂停函数
    int ret = handle->backend->ops->pause(handle->backend);
    if (ret == 0) {
        handle->is_paused = true;
    }

    return ret;
}

int capture_resume(capture_handle_t* handle) {
    if (!handle || !handle->backend) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    if (!handle->is_running || !handle->is_paused) {
        return CAPTURE_SUCCESS;
    }

    // 调用后端的恢复函数
    int ret = handle->backend->ops->resume(handle->backend);
    if (ret == 0) {
        handle->is_paused = false;
    }

    return ret;
}

int capture_get_stats(capture_handle_t* handle, capture_stats_t* stats) {
    if (!handle || !handle->backend || !stats) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    // 调用后端的获取统计信息函数
    return handle->backend->ops->get_stats(handle->backend, stats);
}

int capture_set_filter(capture_handle_t* handle, const char* filter) {
    if (!handle || !handle->backend || !filter) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    // 调用后端的设置过滤器函数
    return handle->backend->ops->set_filter(handle->backend, filter);
}

void capture_cleanup(capture_handle_t* handle) {
    if (!handle) {
        return;
    }

    // 如果还在运行，先停止捕获
    if (handle->is_running) {
        capture_stop(handle);
    }

    // 清理后端
    if (handle->backend) {
        handle->backend->ops->cleanup(handle->backend);
        handle->backend = NULL;
    }

    // 清理句柄
    free(handle);
} 