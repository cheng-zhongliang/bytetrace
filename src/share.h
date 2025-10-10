#ifndef __BYE_SHARE_H__
#define __BYE_SHARE_H__

#ifdef __USER_SPACE__
#define s_uint8 uint8_t
#define s_uint16 uint16_t
#define s_uint32 uint32_t
#define s_uint64 uint64_t
#elif __KERNEL_SPACE__
#define s_uint8 u8
#define s_uint16 u16
#define s_uint32 u32
#define s_uint64 u64
#else
#error "Please define __USER_SPACE__ or __KERNEL_SPACE__"
#endif

struct option {
    char iface[16];
    s_uint16 length;
    s_uint8 vlan_id;
    s_uint8 vlan_prio;
    s_uint8 src_mac[6];
    s_uint8 dst_mac[6];
    s_uint16 l3_proto;
    s_uint8 l4_proto;
    s_uint32 src_ip;
    s_uint32 dst_ip;
    s_uint8 src_ipv6[16];
    s_uint8 dst_ipv6[16];
    s_uint16 src_port;
    s_uint16 dst_port;
};

struct event {
    char iface[16];
    s_uint16 length;
    s_uint8 vlan_id;
    s_uint8 vlan_prio;
    s_uint8 src_mac[6];
    s_uint8 dst_mac[6];
    s_uint16 l3_proto;
    s_uint8 l4_proto;
    s_uint32 src_ip;
    s_uint32 dst_ip;
    s_uint8 src_ipv6[16];
    s_uint8 dst_ipv6[16];
    s_uint16 src_port;
    s_uint16 dst_port;
    s_uint16 reason;
    s_uint32 stack_id;
    s_uint64 location;
    s_uint64 timestamp;
};

#endif