#ifndef BYTETRACE_ABI_H
#define BYTETRACE_ABI_H

#include <stdint.h>

struct trace_event {
    uint64_t timestamp_ns;
    uint32_t ifindex;

    uint32_t packet_len;

    uint8_t src_mac[6];
    uint8_t dst_mac[6];

    uint16_t vlan_id;
    uint8_t vlan_prio;

    uint8_t ip_version;
    uint8_t ip_proto;
    uint16_t eth_proto;

    uint16_t src_port;
    uint16_t dst_port;

    union {
        struct {
            uint32_t src;
            uint32_t dst;
        } ipv4;

        struct {
            uint8_t src[16];
            uint8_t dst[16];
        } ipv6;
    } address;

    uint32_t drop_reason;
    uint32_t location_id;
};


#endif