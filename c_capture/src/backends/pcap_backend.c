#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include "../../include/backends/pcap_backend.h"
#include "../../include/capture_types.h"

struct pcap_backend {
    pcap_t* handle;
    char* device;
    char* filter;
    int snaplen;
    int timeout_ms;
    bool promiscuous;
    bool immediate;
    uint32_t buffer_size;
    packet_callback_t packet_cb;
    error_callback_t error_cb;
    void* user_data;
    void* error_user_data;
    bool running;
};

static void pcap_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    struct pcap_backend* backend = (struct pcap_backend*)user;
    if (!backend->running) {
        return;
    }

    packet_t pkt = {
        .data = packet,
        .len = header->len,
        .caplen = header->caplen,
        .ts = header->ts,
        .if_index = 0,  // TODO: 获取接口索引
        .flags = 0,
        .protocol = 0,  // TODO: 解析协议类型
        .vlan_tci = 0,
        .hash = 0,
    };

    if (!backend->packet_cb(&pkt, backend->user_data)) {
        backend->running = false;
    }
}

capture_handle_t* pcap_backend_init(
    const capture_config_t* config,
    packet_callback_t packet_cb,
    error_callback_t error_cb,
    void* user_data,
    void* error_user_data
) {
    if (!config || !packet_cb || !error_cb) {
        return NULL;
    }

    struct pcap_backend* backend = calloc(1, sizeof(struct pcap_backend));
    if (!backend) {
        return NULL;
    }

    backend->device = strdup(config->device);
    backend->filter = config->filter ? strdup(config->filter) : NULL;
    backend->snaplen = config->snaplen;
    backend->timeout_ms = config->timeout_ms;
    backend->promiscuous = config->promiscuous;
    backend->immediate = config->immediate;
    backend->buffer_size = config->buffer_size;
    backend->packet_cb = packet_cb;
    backend->error_cb = error_cb;
    backend->user_data = user_data;
    backend->error_user_data = error_user_data;
    backend->running = false;

    char errbuf[PCAP_ERRBUF_SIZE];
    backend->handle = pcap_create(backend->device, errbuf);
    if (!backend->handle) {
        error_cb(errbuf, error_user_data);
        free(backend->device);
        free(backend->filter);
        free(backend);
        return NULL;
    }

    if (pcap_set_snaplen(backend->handle, backend->snaplen) != 0) {
        error_cb(pcap_geterr(backend->handle), error_user_data);
        pcap_close(backend->handle);
        free(backend->device);
        free(backend->filter);
        free(backend);
        return NULL;
    }

    if (pcap_set_promisc(backend->handle, backend->promiscuous) != 0) {
        error_cb(pcap_geterr(backend->handle), error_user_data);
        pcap_close(backend->handle);
        free(backend->device);
        free(backend->filter);
        free(backend);
        return NULL;
    }

    if (pcap_set_timeout(backend->handle, backend->timeout_ms) != 0) {
        error_cb(pcap_geterr(backend->handle), error_user_data);
        pcap_close(backend->handle);
        free(backend->device);
        free(backend->filter);
        free(backend);
        return NULL;
    }

    if (pcap_set_buffer_size(backend->handle, backend->buffer_size) != 0) {
        error_cb(pcap_geterr(backend->handle), error_user_data);
        pcap_close(backend->handle);
        free(backend->device);
        free(backend->filter);
        free(backend);
        return NULL;
    }

    if (pcap_activate(backend->handle) != 0) {
        error_cb(pcap_geterr(backend->handle), error_user_data);
        pcap_close(backend->handle);
        free(backend->device);
        free(backend->filter);
        free(backend);
        return NULL;
    }

    if (backend->filter) {
        struct bpf_program fp;
        if (pcap_compile(backend->handle, &fp, backend->filter, 0, PCAP_NETMASK_UNKNOWN) != 0) {
            error_cb(pcap_geterr(backend->handle), error_user_data);
            pcap_close(backend->handle);
            free(backend->device);
            free(backend->filter);
            free(backend);
            return NULL;
        }

        if (pcap_setfilter(backend->handle, &fp) != 0) {
            error_cb(pcap_geterr(backend->handle), error_user_data);
            pcap_freecode(&fp);
            pcap_close(backend->handle);
            free(backend->device);
            free(backend->filter);
            free(backend);
            return NULL;
        }

        pcap_freecode(&fp);
    }

    return (capture_handle_t*)backend;
}

int pcap_backend_start(capture_handle_t* handle) {
    struct pcap_backend* backend = (struct pcap_backend*)handle;
    if (!backend || !backend->handle) {
        return -1;
    }

    backend->running = true;
    return pcap_loop(backend->handle, -1, pcap_callback, (u_char*)backend);
}

int pcap_backend_stop(capture_handle_t* handle) {
    struct pcap_backend* backend = (struct pcap_backend*)handle;
    if (!backend) {
        return -1;
    }

    backend->running = false;
    return 0;
}

void pcap_backend_cleanup(capture_handle_t* handle) {
    struct pcap_backend* backend = (struct pcap_backend*)handle;
    if (!backend) {
        return;
    }

    if (backend->handle) {
        pcap_close(backend->handle);
    }

    free(backend->device);
    free(backend->filter);
    free(backend);
}

int pcap_backend_get_stats(capture_handle_t* handle, capture_stats_t* stats) {
    struct pcap_backend* backend = (struct pcap_backend*)handle;
    if (!backend || !backend->handle || !stats) {
        return -1;
    }

    struct pcap_stat pcap_stats;
    if (pcap_stats(backend->handle, &pcap_stats) != 0) {
        return -1;
    }

    stats->packets_received = pcap_stats.ps_recv;
    stats->packets_dropped = pcap_stats.ps_drop;
    stats->packets_if_dropped = pcap_stats.ps_ifdrop;
    stats->bytes_received = 0;  // TODO: 统计字节数

    return 0;
}

// libpcap 后端私有数据
typedef struct {
    pcap_t* pcap;                    // libpcap 句柄
    pcap_backend_config_t config;    // 配置信息
    bool is_running;                 // 是否正在运行
    bool is_paused;                  // 是否暂停
    capture_stats_t stats;           // 统计信息
    struct timespec start_time;      // 开始时间
} pcap_backend_private_t;

// 内部函数声明
static int pcap_backend_init(void* backend, const capture_config_t* config);
static void pcap_backend_cleanup(void* backend);
static int pcap_backend_open(void* backend, const char* device);
static int pcap_backend_close(void* backend);
static int pcap_backend_start(void* backend, packet_callback_t callback, void* user_data);
static int pcap_backend_stop(void* backend);
static int pcap_backend_pause(void* backend);
static int pcap_backend_resume(void* backend);
static int pcap_backend_set_filter(void* backend, const char* filter);
static int pcap_backend_get_stats(void* backend, capture_stats_t* stats);
static int pcap_backend_get_devices(void* backend, capture_device_t** devices, int* count);
static void pcap_backend_free_devices(void* backend, capture_device_t* devices, int count);
static const char* pcap_backend_get_name(void* backend);
static const char* pcap_backend_get_version(void* backend);
static const char* pcap_backend_get_description(void* backend);
static bool pcap_backend_is_feature_supported(void* backend, const char* feature);
static int pcap_backend_set_option(void* backend, const char* option, const void* value);
static int pcap_backend_get_option(void* backend, const char* option, void* value);

// 操作函数表
static capture_backend_ops_t pcap_backend_ops = {
    .init = pcap_backend_init,
    .cleanup = pcap_backend_cleanup,
    .open = pcap_backend_open,
    .close = pcap_backend_close,
    .start = pcap_backend_start,
    .stop = pcap_backend_stop,
    .pause = pcap_backend_pause,
    .resume = pcap_backend_resume,
    .set_filter = pcap_backend_set_filter,
    .get_stats = pcap_backend_get_stats,
    .get_devices = pcap_backend_get_devices,
    .free_devices = pcap_backend_free_devices,
    .get_name = pcap_backend_get_name,
    .get_version = pcap_backend_get_version,
    .get_description = pcap_backend_get_description,
    .is_feature_supported = pcap_backend_is_feature_supported,
    .set_option = pcap_backend_set_option,
    .get_option = pcap_backend_get_option,
};

// 创建 libpcap 后端
capture_backend_t* pcap_backend_create(
    const pcap_backend_config_t* config,
    error_callback_t error_cb,
    void* error_user_data
) {
    if (!config || !error_cb) {
        return NULL;
    }

    // 分配后端结构
    capture_backend_t* backend = (capture_backend_t*)calloc(1, sizeof(capture_backend_t));
    if (!backend) {
        return NULL;
    }

    // 分配私有数据
    pcap_backend_private_t* private_data = (pcap_backend_private_t*)calloc(1, sizeof(pcap_backend_private_t));
    if (!private_data) {
        free(backend);
        return NULL;
    }

    // 初始化私有数据
    memcpy(&private_data->config, config, sizeof(pcap_backend_config_t));
    private_data->pcap = NULL;
    private_data->is_running = false;
    private_data->is_paused = false;
    memset(&private_data->stats, 0, sizeof(capture_stats_t));

    // 初始化后端结构
    backend->private_data = private_data;
    backend->ops = &pcap_backend_ops;
    backend->type = CAPTURE_BACKEND_PCAP;
    backend->error_cb = error_cb;
    backend->error_user_data = error_user_data;

    return backend;
}

// 销毁 libpcap 后端
void pcap_backend_destroy(capture_backend_t* backend) {
    if (!backend) {
        return;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend->private_data;
    if (private_data) {
        if (private_data->pcap) {
            pcap_close(private_data->pcap);
        }
        free(private_data);
    }
    free(backend);
}

// 初始化后端
static int pcap_backend_init(void* backend, const capture_config_t* config) {
    if (!backend || !config) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    
    // 更新配置
    private_data->config.buffer_size = config->buffer_size;
    private_data->config.timeout_ms = config->timeout_ms;
    private_data->config.immediate = config->immediate;
    private_data->config.promiscuous = config->promiscuous;
    private_data->config.snaplen = config->snaplen;
    private_data->config.filter = config->filter;
    private_data->config.device = config->device;

    return CAPTURE_SUCCESS;
}

// 清理后端
static void pcap_backend_cleanup(void* backend) {
    if (!backend) {
        return;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    if (private_data->pcap) {
        pcap_close(private_data->pcap);
    }
}

// 打开设备
static int pcap_backend_open(void* backend, const char* device) {
    if (!backend || !device) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 打开设备
    private_data->pcap = pcap_open_live(
        device,
        private_data->config.snaplen,
        private_data->config.promiscuous ? 1 : 0,
        private_data->config.timeout_ms,
        errbuf
    );

    if (!private_data->pcap) {
        ((capture_backend_t*)backend)->error_cb(errbuf, ((capture_backend_t*)backend)->error_user_data);
        return CAPTURE_ERROR_OPEN_FAILED;
    }

    // 设置缓冲区大小
    if (pcap_set_buffer_size(private_data->pcap, private_data->config.buffer_size) < 0) {
        pcap_close(private_data->pcap);
        private_data->pcap = NULL;
        ((capture_backend_t*)backend)->error_cb("Failed to set buffer size", ((capture_backend_t*)backend)->error_user_data);
        return CAPTURE_ERROR_INIT_FAILED;
    }

    // 设置立即模式
    if (private_data->config.immediate) {
        if (pcap_set_immediate_mode(private_data->pcap, 1) < 0) {
            pcap_close(private_data->pcap);
            private_data->pcap = NULL;
            ((capture_backend_t*)backend)->error_cb("Failed to set immediate mode", ((capture_backend_t*)backend)->error_user_data);
            return CAPTURE_ERROR_INIT_FAILED;
        }
    }

    // 设置过滤器
    if (private_data->config.filter) {
        struct bpf_program fp;
        if (pcap_compile(private_data->pcap, &fp, private_data->config.filter, 0, PCAP_NETMASK_UNKNOWN) < 0) {
            pcap_close(private_data->pcap);
            private_data->pcap = NULL;
            ((capture_backend_t*)backend)->error_cb("Failed to compile filter", ((capture_backend_t*)backend)->error_user_data);
            return CAPTURE_ERROR_SET_FILTER;
        }

        if (pcap_setfilter(private_data->pcap, &fp) < 0) {
            pcap_freecode(&fp);
            pcap_close(private_data->pcap);
            private_data->pcap = NULL;
            ((capture_backend_t*)backend)->error_cb("Failed to set filter", ((capture_backend_t*)backend)->error_user_data);
            return CAPTURE_ERROR_SET_FILTER;
        }

        pcap_freecode(&fp);
    }

    return CAPTURE_SUCCESS;
}

// 关闭设备
static int pcap_backend_close(void* backend) {
    if (!backend) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    if (private_data->pcap) {
        pcap_close(private_data->pcap);
        private_data->pcap = NULL;
    }

    return CAPTURE_SUCCESS;
}

// 数据包回调包装函数
static void pcap_packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    capture_backend_t* backend = (capture_backend_t*)user;
    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend->private_data;
    packet_callback_t callback = (packet_callback_t)private_data->user_data;

    // 更新统计信息
    private_data->stats.packets_received++;
    private_data->stats.bytes_received += header->len;

    // 构造数据包结构
    packet_t pkt = {
        .data = (uint8_t*)packet,
        .len = header->len,
        .caplen = header->caplen,
        .ts = header->ts,
        .if_index = 0,  // TODO: 获取接口索引
        .flags = 0,
        .protocol = 0,  // TODO: 解析协议类型
        .vlan_tci = 0,
        .hash = 0
    };

    // 调用用户回调
    if (!callback(&pkt, private_data->user_data)) {
        private_data->is_running = false;
    }
}

// 开始抓包
static int pcap_backend_start(void* backend, packet_callback_t callback, void* user_data) {
    if (!backend || !callback) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    if (!private_data->pcap) {
        return CAPTURE_ERROR_NOT_SUPPORTED;
    }

    if (private_data->is_running) {
        return CAPTURE_SUCCESS;
    }

    // 保存回调信息
    private_data->user_data = user_data;
    private_data->is_running = true;
    private_data->is_paused = false;

    // 记录开始时间
    clock_gettime(CLOCK_MONOTONIC, &private_data->start_time);
    private_data->stats.start_time = private_data->start_time;

    // 开始抓包
    int ret = pcap_loop(private_data->pcap, -1, pcap_packet_handler, (u_char*)backend);
    if (ret < 0) {
        private_data->is_running = false;
        if (ret == -2) {
            return CAPTURE_SUCCESS;  // 正常停止
        }
        ((capture_backend_t*)backend)->error_cb(pcap_geterr(private_data->pcap), ((capture_backend_t*)backend)->error_user_data);
        return CAPTURE_ERROR_BACKEND;
    }

    return CAPTURE_SUCCESS;
}

// 停止抓包
static int pcap_backend_stop(void* backend) {
    if (!backend) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    if (!private_data->pcap || !private_data->is_running) {
        return CAPTURE_SUCCESS;
    }

    private_data->is_running = false;
    pcap_breakloop(private_data->pcap);

    // 记录结束时间
    clock_gettime(CLOCK_MONOTONIC, &private_data->stats.end_time);

    return CAPTURE_SUCCESS;
}

// 暂停抓包
static int pcap_backend_pause(void* backend) {
    if (!backend) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    if (!private_data->pcap || !private_data->is_running || private_data->is_paused) {
        return CAPTURE_SUCCESS;
    }

    private_data->is_paused = true;
    // TODO: 实现暂停功能

    return CAPTURE_SUCCESS;
}

// 恢复抓包
static int pcap_backend_resume(void* backend) {
    if (!backend) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    if (!private_data->pcap || !private_data->is_running || !private_data->is_paused) {
        return CAPTURE_SUCCESS;
    }

    private_data->is_paused = false;
    // TODO: 实现恢复功能

    return CAPTURE_SUCCESS;
}

// 设置过滤器
static int pcap_backend_set_filter(void* backend, const char* filter) {
    if (!backend || !filter) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    if (!private_data->pcap) {
        return CAPTURE_ERROR_NOT_SUPPORTED;
    }

    struct bpf_program fp;
    if (pcap_compile(private_data->pcap, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) < 0) {
        ((capture_backend_t*)backend)->error_cb(pcap_geterr(private_data->pcap), ((capture_backend_t*)backend)->error_user_data);
        return CAPTURE_ERROR_SET_FILTER;
    }

    if (pcap_setfilter(private_data->pcap, &fp) < 0) {
        pcap_freecode(&fp);
        ((capture_backend_t*)backend)->error_cb(pcap_geterr(private_data->pcap), ((capture_backend_t*)backend)->error_user_data);
        return CAPTURE_ERROR_SET_FILTER;
    }

    pcap_freecode(&fp);
    return CAPTURE_SUCCESS;
}

// 获取统计信息
static int pcap_backend_get_stats(void* backend, capture_stats_t* stats) {
    if (!backend || !stats) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    pcap_backend_private_t* private_data = (pcap_backend_private_t*)backend;
    if (!private_data->pcap) {
        return CAPTURE_ERROR_NOT_SUPPORTED;
    }

    struct pcap_stat pcap_stats;
    if (pcap_stats(private_data->pcap, &pcap_stats) < 0) {
        ((capture_backend_t*)backend)->error_cb(pcap_geterr(private_data->pcap), ((capture_backend_t*)backend)->error_user_data);
        return CAPTURE_ERROR_GET_STATS;
    }

    // 更新统计信息
    private_data->stats.packets_dropped = pcap_stats.ps_drop;
    private_data->stats.packets_if_dropped = pcap_stats.ps_ifdrop;

    // 复制统计信息
    memcpy(stats, &private_data->stats, sizeof(capture_stats_t));

    return CAPTURE_SUCCESS;
}

// 获取设备列表
static int pcap_backend_get_devices(void* backend, capture_device_t** devices, int* count) {
    if (!backend || !devices || !count) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        ((capture_backend_t*)backend)->error_cb(errbuf, ((capture_backend_t*)backend)->error_user_data);
        return CAPTURE_ERROR_GET_DEVICES;
    }

    // 计算设备数量
    int dev_count = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        dev_count++;
    }

    // 分配设备列表
    capture_device_t* dev_list = (capture_device_t*)calloc(dev_count, sizeof(capture_device_t));
    if (!dev_list) {
        pcap_freealldevs(alldevs);
        return CAPTURE_ERROR_MEMORY;
    }

    // 填充设备信息
    int i = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        capture_device_t* dev = &dev_list[i++];
        
        // 复制设备名称
        strncpy(dev->name, d->name, sizeof(dev->name) - 1);
        
        // 复制设备描述
        if (d->description) {
            strncpy(dev->description, d->description, sizeof(dev->description) - 1);
        }

        // 设置设备标志
        dev->flags = 0;
        if (d->flags & PCAP_IF_UP) {
            dev->flags |= CAPTURE_DEVICE_FLAG_UP;
        }
        if (d->flags & PCAP_IF_RUNNING) {
            dev->flags |= CAPTURE_DEVICE_FLAG_RUNNING;
        }
        if (d->flags & PCAP_IF_LOOPBACK) {
            dev->flags |= CAPTURE_DEVICE_FLAG_LOOPBACK;
        }

        // 设置设备类型
        if (d->flags & PCAP_IF_LOOPBACK) {
            dev->type = CAPTURE_DEVICE_TYPE_LOOPBACK;
        } else {
            dev->type = CAPTURE_DEVICE_TYPE_ETHERNET;
        }

        // TODO: 获取更多设备信息（MTU、速度、MAC地址等）
    }

    pcap_freealldevs(alldevs);
    *devices = dev_list;
    *count = dev_count;

    return CAPTURE_SUCCESS;
}

// 释放设备列表
static void pcap_backend_free_devices(void* backend, capture_device_t* devices, int count) {
    if (devices) {
        free(devices);
    }
}

// 获取后端名称
static const char* pcap_backend_get_name(void* backend) {
    return "libpcap";
}

// 获取后端版本
static const char* pcap_backend_get_version(void* backend) {
    return pcap_lib_version();
}

// 获取后端描述
static const char* pcap_backend_get_description(void* backend) {
    return "libpcap packet capture backend";
}

// 检查后端是否支持特定功能
static bool pcap_backend_is_feature_supported(void* backend, const char* feature) {
    if (!feature) {
        return false;
    }

    // TODO: 实现功能检查
    return false;
}

// 设置后端特定选项
static int pcap_backend_set_option(void* backend, const char* option, const void* value) {
    if (!backend || !option || !value) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    // TODO: 实现选项设置
    return CAPTURE_ERROR_NOT_SUPPORTED;
}

// 获取后端特定选项
static int pcap_backend_get_option(void* backend, const char* option, void* value) {
    if (!backend || !option || !value) {
        return CAPTURE_ERROR_INVALID_PARAM;
    }

    // TODO: 实现选项获取
    return CAPTURE_ERROR_NOT_SUPPORTED;
} 