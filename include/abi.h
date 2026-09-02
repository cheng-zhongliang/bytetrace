#ifndef BYTETRACE_ABI_H
#define BYTETRACE_ABI_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

enum trace_filter {
    TRACE_FILTER_NONE = 0,
    TRACE_FILTER_IFACE = 1U << 0,
    TRACE_FILTER_PACKET_LEN = 1U << 1,
    TRACE_FILTER_SRC_MAC = 1U << 2,
    TRACE_FILTER_DST_MAC = 1U << 3,
    TRACE_FILTER_VLAN_ID = 1U << 4,
    TRACE_FILTER_VLAN_PRIO = 1U << 5,
    TRACE_FILTER_ETH_PROTO = 1U << 6,
    TRACE_FILTER_SRC_IP = 1U << 7,
    TRACE_FILTER_DST_IP = 1U << 8,
    TRACE_FILTER_IP_PROTO = 1U << 9,
    TRACE_FILTER_SRC_PORT = 1U << 10,
    TRACE_FILTER_DST_PORT = 1U << 11,
};

struct trace_config {
    __u32 filters;

    __u32 ifindex;
    __u32 packet_len;

    __u8 src_mac[6];
    __u8 dst_mac[6];

    __u16 vlan_id;
    __u8 vlan_prio;
    __u8 ip_version;

    __u16 eth_proto;
    __u8 ip_proto;
    __u8 ratelimit;

    __u16 src_port;
    __u16 dst_port;

    union {
        struct {
            __be32 src;
            __be32 dst;
        } ipv4;

        struct {
            __u8 src[16];
            __u8 dst[16];
        } ipv6;
    } address;
};

struct trace_event {
    __u64 timestamp_ns;
    __u32 ifindex;

    __u32 packet_len;

    __u8 src_mac[6];
    __u8 dst_mac[6];

    __u16 vlan_id;
    __u8 vlan_prio;

    __u8 ip_version;
    __u8 ip_proto;
    __u16 eth_proto;

    __u16 src_port;
    __u16 dst_port;

    union {
        struct {
            __u32 src;
            __u32 dst;
        } ipv4;

        struct {
            __u8 src[16];
            __u8 dst[16];
        } ipv6;
    } address;

    __u32 drop_reason;
    __u32 location_id;
};


#endif
