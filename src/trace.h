#ifndef TRACE_H
#define TRACE_H

#include <stdbool.h>
#include <stdint.h>

#include "abi.h"

struct trace_config {
    const char* btf_path;
    bool ratelimit;
    uint32_t filters;

    char iface[16];

    uint8_t src_mac[6];
    uint8_t dst_mac[6];

    uint16_t vlan_id;
    uint8_t vlan_prio;
    uint16_t eth_proto;

    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t src_ipv6[16];
    uint8_t dst_ipv6[16];

    uint8_t ip_proto;
    uint16_t src_port;
    uint16_t dst_port;
};

struct trace_context;

typedef void (*trace_event_callback)(const struct trace_event* event, void* data);

struct trace_context*
trace_context_new(const struct trace_config* config, trace_event_callback cb, void* data);
void trace_context_free(struct trace_context* ctx);
int trace_context_dispatch(struct trace_context* ctx, int timeout_ms);

#endif
