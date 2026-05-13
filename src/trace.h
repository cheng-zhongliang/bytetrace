#ifndef TRACE_H
#define TRACE_H

#include <stdbool.h>
#include <stdint.h>

struct trace_config {
    char* btf_path;
    bool ratelimit;
    uint32_t filter_mask;

    char iface[16];
    uint8_t vlan_id;
    uint8_t vlan_prio;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t l3_proto;
    uint8_t l4_proto;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t src_ipv6[16];
    uint8_t dst_ipv6[16];
    uint16_t src_port;
    uint16_t dst_port;
};

struct trace_context;

struct trace_context* trace_new(const struct trace_config* config);
void trace_free(struct trace_context* ctx);
int trace_dispatch(struct trace_context* ctx);

#endif
