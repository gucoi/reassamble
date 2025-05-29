#ifndef CAPTURE_TYPES_H
#define CAPTURE_TYPES_H

#include <stdint.h>
#include <time.h>

/**
 * 数据包结构
 */
typedef struct {
    const uint8_t* data;     // 数据包内容
    uint32_t len;            // 数据包长度
    uint32_t caplen;         // 捕获长度
    struct timespec ts;      // 时间戳
    uint32_t if_index;       // 接口索引
    uint32_t flags;          // 标志位
    uint32_t protocol;       // 协议类型
    uint32_t vlan_tci;       // VLAN 标签
    uint32_t hash;           // 数据包哈希值
} packet_t;

/**
 * 设备信息结构
 */
typedef struct {
    char name[32];           // 设备名称
    char description[256];   // 设备描述
    uint32_t flags;          // 设备标志
    uint32_t type;           // 设备类型
    uint32_t mtu;            // MTU 大小
    uint32_t speed;          // 接口速度
    uint8_t mac[6];          // MAC 地址
    uint32_t ipv4;           // IPv4 地址
    uint32_t netmask;        // 子网掩码
    uint32_t broadcast;      // 广播地址
} capture_device_t;

/**
 * 统计信息结构
 */
typedef struct {
    uint64_t packets_received;    // 接收的数据包数
    uint64_t packets_dropped;     // 丢弃的数据包数
    uint64_t packets_if_dropped;  // 接口丢弃的数据包数
    uint64_t bytes_received;      // 接收的字节数
    struct timespec start_time;   // 开始时间
    struct timespec end_time;     // 结束时间
} capture_stats_t;

/**
 * 错误码定义
 */
typedef enum {
    CAPTURE_SUCCESS = 0,           // 成功
    CAPTURE_ERROR_INVALID_PARAM,   // 无效参数
    CAPTURE_ERROR_INIT_FAILED,     // 初始化失败
    CAPTURE_ERROR_OPEN_FAILED,     // 打开设备失败
    CAPTURE_ERROR_SET_FILTER,      // 设置过滤器失败
    CAPTURE_ERROR_START_FAILED,    // 启动失败
    CAPTURE_ERROR_STOP_FAILED,     // 停止失败
    CAPTURE_ERROR_PAUSE_FAILED,    // 暂停失败
    CAPTURE_ERROR_RESUME_FAILED,   // 恢复失败
    CAPTURE_ERROR_GET_STATS,       // 获取统计信息失败
    CAPTURE_ERROR_GET_DEVICES,     // 获取设备列表失败
    CAPTURE_ERROR_NOT_SUPPORTED,   // 不支持的操作
    CAPTURE_ERROR_BACKEND,         // 后端错误
    CAPTURE_ERROR_MEMORY,          // 内存错误
    CAPTURE_ERROR_TIMEOUT,         // 超时错误
    CAPTURE_ERROR_INTERNAL,        // 内部错误
} capture_error_t;

/**
 * 设备标志位定义
 */
#define CAPTURE_DEVICE_FLAG_UP           0x0001  // 接口处于活动状态
#define CAPTURE_DEVICE_FLAG_RUNNING      0x0002  // 接口正在运行
#define CAPTURE_DEVICE_FLAG_PROMISC      0x0004  // 支持混杂模式
#define CAPTURE_DEVICE_FLAG_LOOPBACK     0x0008  // 回环接口
#define CAPTURE_DEVICE_FLAG_WIRELESS     0x0010  // 无线接口
#define CAPTURE_DEVICE_FLAG_VIRTUAL      0x0020  // 虚拟接口
#define CAPTURE_DEVICE_FLAG_HAS_IPV4     0x0040  // 有 IPv4 地址
#define CAPTURE_DEVICE_FLAG_HAS_IPV6     0x0080  // 有 IPv6 地址

/**
 * 设备类型定义
 */
typedef enum {
    CAPTURE_DEVICE_TYPE_ETHERNET = 1,    // 以太网
    CAPTURE_DEVICE_TYPE_WIFI,            // WiFi
    CAPTURE_DEVICE_TYPE_LOOPBACK,        // 回环
    CAPTURE_DEVICE_TYPE_TUN,             // TUN
    CAPTURE_DEVICE_TYPE_TAP,             // TAP
    CAPTURE_DEVICE_TYPE_BRIDGE,          // 网桥
    CAPTURE_DEVICE_TYPE_VLAN,            // VLAN
    CAPTURE_DEVICE_TYPE_BOND,            // 绑定
    CAPTURE_DEVICE_TYPE_VETH,            // 虚拟以太网
    CAPTURE_DEVICE_TYPE_OTHER,           // 其他
} capture_device_type_t;

#endif // CAPTURE_TYPES_H 