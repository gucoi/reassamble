#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include "../../include/backends/pcap_backend.h"
#include "../../include/capture_types.h"

struct pcap_backend {
    capture_backend_t base;          // 基础后端结构
    pcap_t* handle;                  // libpcap 句柄
    char* device;                    // 设备名称
    char* filter;                    // 过滤器
    int snaplen;                     // 抓包长度
    int timeout_ms;                  // 超时时间
    bool promiscuous;                // 是否开启混杂模式
    bool immediate;                  // 是否立即返回
    uint32_t buffer_size;            // 缓冲区大小
    packet_callback_t packet_cb;     // 数据包回调
    error_callback_t error_cb;       // 错误回调
    void* user_data;                 // 用户数据
    void* error_user_data;           // 错误回调用户数据
    bool running;                    // 是否正在运行
};

// 内部函数声明
static void pcap_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
static int pcap_backend_open(void* backend, const char* device);
static int pcap_backend_close(void* backend);
static int pcap_backend_get_devices(void* backend, capture_device_t** devices, int* count);
static void pcap_backend_free_devices(void* backend, capture_device_t* devices, int count);
static const char* pcap_backend_get_name(void* backend);
static const char* pcap_backend_get_description(void* backend);

// 公共接口实现
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

// pcap_callback 回调实现，修正 .ts 字段类型
static void pcap_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    struct pcap_backend* backend = (struct pcap_backend*)user;
    printf("[pcap_callback] enter, backend=%p, running=%d, user_data=%p\n", 
           backend, backend ? backend->running : -1, backend ? backend->user_data : NULL);
    
    if (!backend) {
        printf("[pcap_callback] ERROR: backend is NULL\n");
        return;
    }
    
    if (!backend->running) {
        printf("[pcap_callback] backend not running, return\n");
        return;
    }
    
    if (!backend->packet_cb) {
        printf("[pcap_callback] ERROR: packet_cb is NULL\n");
        return;
    }
    
    struct timespec ts;
    ts.tv_sec = header->ts.tv_sec;
    ts.tv_nsec = header->ts.tv_usec * 1000;
    packet_t pkt = {
        .data = packet,
        .len = header->len,
        .caplen = header->caplen,
        .ts = ts,
        .if_index = 0,
        .flags = 0,
        .protocol = 0,
        .vlan_tci = 0,
        .hash = 0,
    };
    
    printf("[pcap_callback] before user callback, packet len=%d, caplen=%d\n", 
           pkt.len, pkt.caplen);
           
    if (!backend->packet_cb(&pkt, backend->user_data)) {
        printf("[pcap_callback] user callback returned false, set running=0\n");
        backend->running = false;
    }
    printf("[pcap_callback] leave\n");
}

int pcap_backend_start(capture_handle_t* handle, packet_callback_t packet_cb, void* user_data) {
    struct pcap_backend* backend = (struct pcap_backend*)handle;
    printf("[pcap_backend_start] enter, handle=%p, backend=%p, packet_cb=%p, user_data=%p\n",
           handle, backend, packet_cb, user_data);
           
    if (!backend || !backend->handle) {
        printf("[pcap_backend_start] ERROR: Invalid handle or backend\n");
        return -1;
    }
    
    backend->user_data = user_data;
    backend->packet_cb = packet_cb;  // 确保设置回调函数
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* test_handle = pcap_open_live(backend->device, backend->snaplen, 
                                        backend->promiscuous, 1000, errbuf);
    if (!test_handle) {
        printf("[pcap_backend_start] ERROR: Device not available: %s\n", errbuf);
        return -1;
    }
    pcap_close(test_handle);
    
    printf("[pcap_backend_start] Starting capture on device %s\n", backend->device);
    backend->running = true;
    
    int ret = pcap_loop(backend->handle, 10, pcap_callback, (u_char*)backend);
    if (ret < 0) {
        printf("[pcap_backend_start] ERROR: pcap_loop failed: %s\n", pcap_geterr(backend->handle));
        backend->running = false;
        return -1;
    }
    
    printf("[pcap_backend_start] leave, ret=%d\n", ret);
    return ret;
}

int pcap_backend_stop(capture_handle_t* handle) {
    struct pcap_backend* backend = (struct pcap_backend*)handle;
    printf("[pcap_backend_stop] enter, handle=%p, backend=%p, running=%d\n", 
           handle, backend, backend ? backend->running : -1);
           
    if (!backend) {
        printf("[pcap_backend_stop] ERROR: backend is NULL\n");
        return -1;
    }
    
    backend->running = false;
    if (backend->handle) {
        printf("[pcap_backend_stop] calling pcap_breakloop, handle=%p\n", backend->handle);
        pcap_breakloop(backend->handle);
        usleep(100000);  // 等待100ms确保回调完成
        
        if (backend->handle) {
            printf("[pcap_backend_stop] calling pcap_close, handle=%p\n", backend->handle);
            pcap_close(backend->handle);
            backend->handle = NULL;
        }
    }
    
    printf("[pcap_backend_stop] leave\n");
    return 0;
}

void pcap_backend_cleanup(capture_handle_t* handle) {
    struct pcap_backend* backend = (struct pcap_backend*)handle;
    printf("[pcap_backend_cleanup] called, handle=%p, backend=%p\n", handle, backend);
    if (!backend) {
        printf("[pcap_backend_cleanup] backend is NULL\n");
        return;
    }
    if (backend->running) {
        printf("[pcap_backend_cleanup] backend running, call stop\n");
        pcap_backend_stop(handle);
    }
    if (backend->filter) {
        printf("[pcap_backend_cleanup] free filter %p\n", backend->filter);
        free(backend->filter);
        backend->filter = NULL;
    }
    printf("[pcap_backend_cleanup] free backend struct %p\n", backend);
    free(backend);
}

int pcap_backend_get_stats(capture_handle_t* handle, capture_stats_t* stats) {
    struct pcap_backend* backend = (struct pcap_backend*)handle;
    if (!backend || !backend->handle || !stats) {
        return -1;
    }
    struct pcap_stat stat_info;
    if (pcap_stats(backend->handle, &stat_info) != 0) {
        return -1;
    }
    stats->packets_received = stat_info.ps_recv;
    stats->packets_dropped = stat_info.ps_drop;
    stats->packets_if_dropped = stat_info.ps_ifdrop;
    return 0;
}

const char* pcap_backend_get_version(void) {
    return pcap_lib_version();
}

bool pcap_backend_is_feature_supported(const char* feature) {
    // TODO: 实现功能检查
    return false;
}

int pcap_backend_set_option(
    capture_backend_t* backend,
    const char* option,
    const void* value
) {
    // TODO: 实现选项设置
    return CAPTURE_ERROR_NOT_SUPPORTED;
}

int pcap_backend_get_option(
    capture_backend_t* backend,
    const char* option,
    void* value
) {
    // TODO: 实现选项获取
    return CAPTURE_ERROR_NOT_SUPPORTED;
}

// libpcap 后端私有数据
typedef struct {
    pcap_t* pcap;                    // libpcap 句柄
    pcap_backend_config_t config;    // 配置信息
    bool is_running;                 // 是否正在运行
    bool is_paused;                  // 是否暂停
    capture_stats_t stats;           // 统计信息
    struct timespec start_time;      // 开始时间
    void* user_data;                 // 用户数据
} pcap_backend_private_t;

// 操作函数表
static capture_backend_ops_t pcap_backend_ops = {
    .init = pcap_backend_init,
    .cleanup = pcap_backend_cleanup,
    .open = pcap_backend_open,
    .close = pcap_backend_close,
    .start = pcap_backend_start,
    .stop = pcap_backend_stop,
    .pause = NULL,
    .resume = NULL,
    .set_filter = NULL,
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
    printf("[pcap_backend_create] called, config=%p\n", config);
    if (config) {
        printf("[pcap_backend_create] device ptr=%p, filter ptr=%p\n", config->device, config->filter);
        if (config->device) printf("[pcap_backend_create] device str=%s\n", config->device);
        if (config->filter) printf("[pcap_backend_create] filter str=%s\n", config->filter);
    }
    if (!config || !error_cb) {
        return NULL;
    }

    // 分配后端结构
    struct pcap_backend* backend = calloc(1, sizeof(struct pcap_backend));
    printf("[pcap_backend_create] backend struct allocated at %p\n", backend);
    if (!backend) {
        printf("[pcap_backend_create] backend allocation failed\n");
        return NULL;
    }

    // 初始化基础后端结构
    backend->base.private_data = backend;
    backend->base.ops = &pcap_backend_ops;
    backend->base.type = CAPTURE_BACKEND_PCAP;
    backend->base.error_cb = error_cb;
    backend->base.error_user_data = error_user_data;

    backend->device = strdup(config->device);
    printf("[pcap_backend_create] backend->device strdup result: %p, str=%s\n", backend->device, backend->device);
    backend->filter = config->filter ? strdup(config->filter) : NULL;
    if (backend->filter) printf("[pcap_backend_create] backend->filter strdup result: %p, str=%s\n", backend->filter, backend->filter);

    char errbuf[PCAP_ERRBUF_SIZE];
    backend->handle = pcap_create(backend->device, errbuf);
    if (!backend->handle) {
        printf("[pcap_backend_create] pcap_create failed\n");
        error_cb(errbuf, error_user_data);
        free(backend->device);
        free(backend->filter);
        free(backend);
        return NULL;
    }

    if (pcap_set_snaplen(backend->handle, backend->snaplen) != 0) {
        printf("[pcap_backend_create] pcap_set_snaplen failed\n");
        error_cb(pcap_geterr(backend->handle), error_user_data);
        pcap_close(backend->handle);
        free(backend->device);
        free(backend->filter);
        free(backend);
        return NULL;
    }

    if (pcap_set_promisc(backend->handle, backend->promiscuous) != 0) {
        printf("[pcap_backend_create] pcap_set_promisc failed\n");
        error_cb(pcap_geterr(backend->handle), error_user_data);
        pcap_close(backend->handle);
        free(backend->device);
        free(backend->filter);
        free(backend);
        return NULL;
    }

    if (pcap_set_timeout(backend->handle, backend->timeout_ms) != 0) {
        printf("[pcap_backend_create] pcap_set_timeout failed\n");
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

    printf("[pcap_backend_create] success, backend=%p\n", backend);
    return (capture_backend_t*)backend;
}

// 销毁 libpcap 后端
void pcap_backend_destroy(capture_backend_t* backend) {
    printf("[pcap_backend_destroy] called, backend=%p\n", backend);
    if (!backend) {
        printf("[pcap_backend_destroy] backend is NULL\n");
        return;
    }

    struct pcap_backend* pcap_backend = (struct pcap_backend*)backend;
    if (pcap_backend->handle) {
        printf("[pcap_backend_destroy] closing pcap handle %p\n", pcap_backend->handle);
        pcap_close(pcap_backend->handle);
    }
    printf("[pcap_backend_destroy] freeing backend %p\n", backend);
    free(backend);
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

// 获取后端描述
static const char* pcap_backend_get_description(void* backend) {
    return "libpcap packet capture backend";
} 