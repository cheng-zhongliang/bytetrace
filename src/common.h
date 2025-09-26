#ifndef __BYE_COMMON_H__
#define __BYE_COMMON_H__

#define UINT8 uint8_t
#define UINT16 uint16_t
#define UINT32 uint32_t

struct filter_option {
    UINT8 src_mac[6];
    UINT8 dst_mac[6];
    UINT16 l3_proto;
    UINT8 l4_proto;
    UINT32 src_ip;
    UINT32 dst_ip;
    UINT16 src_port;
    UINT16 dst_port;
};

#endif