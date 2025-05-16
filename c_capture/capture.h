#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdint.h>

typedef struct {
    const uint8_t* data;
    size_t len;
    uint64_t timestamp;
} packet_t;

// 统一的捕获接口
typedef struct {
    void* (*init)(const char* config);
    int (*start)(void* handle);
    int (*stop)(void* handle);
    packet_t* (*next_packet)(void* handle);
    void (*cleanup)(void* handle);
} capture_ops_t;

// 各个捕获模块实现这些接口
extern capture_ops_t pcap_ops;
extern capture_ops_t pfring_ops;
extern capture_ops_t dpdk_ops;
extern capture_ops_t afpacket_ops;

#endif
