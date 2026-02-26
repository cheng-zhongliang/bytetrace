#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "share.h"

#define memcmp __builtin_memcmp
#define memcpy __builtin_memcpy

#define VLAN_PRIO_MASK 0xe000
#define VLAN_PRIO_SHIFT 13
#define VLAN_VID_MASK 0x0fff

#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58

#define SKB_MAC_HEADER_INVALID ((u16)~0U)

#define RL_TOKENS_PER_EVENT 60
#define NSEC_PER_SEC 1000000000ULL

#define FILTER_EQ(target, filter_val)            \
    if((filter_val) && (target) != (filter_val)) \
    return -1

#define FILTER_MEM(target, filter_val, flag_val)                    \
    if(flag_val) {                                                  \
        if(memcmp((target), (filter_val), sizeof(filter_val)) != 0) \
            return -1;                                              \
    }

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

static __always_inline u32 sat_add(u32 x, u32 y)
{
    u32 sum = x + y;
    return sum >= x ? sum : ~0u;
}

static __always_inline u32 sat_mul(u32 x, u32 y)
{
    return (!y ? 0 : x <= (~0u) / y ? x * y : ~0u);
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(value, struct option);
    __type(key, u32);
    __uint(max_entries, 1);
} options SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct trace_context {
    struct sk_buff* skb;
    struct option* opt;
    struct event* ev;
};

static __always_inline void rl_refill(struct option* opt, u64 now)
{
    /* last_fill in the future means time went backward or first use */
    if(opt->last_fill > now) {
        opt->tokens = opt->burst;
        opt->last_fill = now;
        return;
    }

    u64 delta_ns = now - opt->last_fill;
    if(delta_ns >= NSEC_PER_SEC) {
        u64 seconds = delta_ns / NSEC_PER_SEC;
        u32 add = sat_mul(opt->rate, seconds);
        u32 tokens = sat_add(opt->tokens, add);
        opt->tokens = MIN(tokens, opt->burst);
        opt->last_fill += seconds * NSEC_PER_SEC;
    }
}

static __always_inline bool rl_allow(struct option* opt, struct event* ev)
{
    if(opt->rate == 0) {
        return true;
    }

    if(opt->tokens < RL_TOKENS_PER_EVENT) {
        rl_refill(opt, ev->timestamp);
        if(opt->tokens < RL_TOKENS_PER_EVENT) {
            return false;
        }
    }
    opt->tokens -= RL_TOKENS_PER_EVENT;

    return true;
}

static __always_inline int match_l4(void* pos, struct option* opt, struct event* ev)
{
    switch(ev->l4_proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP: {
        /* tcphdr and udphdr share the same source/dest layout at offset 0 */
        struct udphdr h;
        bpf_probe_read_kernel(&h, sizeof(h), pos);

        ev->src_port = bpf_ntohs(h.source);
        FILTER_EQ(ev->src_port, opt->src_port);

        ev->dst_port = bpf_ntohs(h.dest);
        FILTER_EQ(ev->dst_port, opt->dst_port);

        break;
    }
    /* ICMP/ICMPv6: no port fields to match, accept as-is */
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
    default: break;
    }

    return 0;
}

static __always_inline int match_l3(void* pos, struct option* opt, struct event* ev)
{
    switch(ev->l3_proto) {
    case ETH_P_IP: {
        struct iphdr iph;
        bpf_probe_read_kernel(&iph, sizeof(iph), pos);
        ev->l4_proto = iph.protocol;

        ev->src_ip = iph.saddr;
        FILTER_EQ(ev->src_ip, opt->src_ip);

        ev->dst_ip = iph.daddr;
        FILTER_EQ(ev->dst_ip, opt->dst_ip);

        pos += iph.ihl * 4;
        break;
    }
    case ETH_P_IPV6: {
        struct ipv6hdr ip6h;
        bpf_probe_read_kernel(&ip6h, sizeof(ip6h), pos);
        ev->l4_proto = ip6h.nexthdr;

        memcpy(ev->src_ipv6, ip6h.saddr.in6_u.u6_addr8, sizeof(ip6h.saddr));
        FILTER_MEM(ev->src_ipv6, opt->src_ipv6, opt->src_ipv6_filter);

        memcpy(ev->dst_ipv6, ip6h.daddr.in6_u.u6_addr8, sizeof(ip6h.daddr));
        FILTER_MEM(ev->dst_ipv6, opt->dst_ipv6, opt->dst_ipv6_filter);

        pos += sizeof(ip6h);
        break;
    }
    default: return 0;
    }

    FILTER_EQ(ev->l4_proto, opt->l4_proto);

    return match_l4(pos, opt, ev);
}

static __always_inline int parse_vlan(void* data, struct event* ev)
{
    struct vlan_hdr vh;
    bpf_probe_read_kernel(&vh, sizeof(vh), data);

    u16 tci = bpf_ntohs(vh.h_vlan_TCI);
    ev->vlan_id = tci & VLAN_VID_MASK;
    ev->vlan_prio = (tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
    ev->l3_proto = bpf_ntohs(vh.h_vlan_encapsulated_proto);

    return sizeof(vh);
}

static __always_inline int match_l2(void* pos, struct option* opt, struct event* ev)
{
    struct ethhdr eth;
    bpf_probe_read_kernel(&eth, sizeof(eth), pos);

    memcpy(ev->dst_mac, eth.h_dest, sizeof(eth.h_dest));
    FILTER_MEM(ev->dst_mac, opt->dst_mac, opt->dst_mac_filter);

    memcpy(ev->src_mac, eth.h_source, sizeof(eth.h_source));
    FILTER_MEM(ev->src_mac, opt->src_mac, opt->src_mac_filter);

    pos += sizeof(eth);

    ev->l3_proto = bpf_ntohs(eth.h_proto);
    if(ev->l3_proto == ETH_P_8021Q || ev->l3_proto == ETH_P_8021AD) {
        pos += parse_vlan(pos, ev);
    }

    FILTER_EQ(ev->vlan_id, opt->vlan_id);
    FILTER_EQ(ev->vlan_prio, opt->vlan_prio);
    FILTER_EQ(ev->l3_proto, opt->l3_proto);

    return match_l3(pos, opt, ev);
}

static __always_inline int
match_skb_meta(struct sk_buff* skb, struct option* opt, struct event* ev)
{
    struct net_device* dev;

    ev->length = BPF_CORE_READ(skb, len);
    FILTER_EQ(ev->length, opt->length);

    dev = BPF_CORE_READ(skb, dev);
    bpf_probe_read_kernel_str(ev->iface, sizeof(ev->iface), dev->name);
    FILTER_MEM(ev->iface, opt->iface, opt->iface[0]);

    return 0;
}

static __always_inline int
match_skb_headers(struct sk_buff* skb, struct option* opt, struct event* ev)
{
    void *head, *pos;
    u16 mac_header;
    u16 network_header;

    head = BPF_CORE_READ(skb, head);
    mac_header = BPF_CORE_READ(skb, mac_header);
    network_header = BPF_CORE_READ(skb, network_header);

    if(mac_header == SKB_MAC_HEADER_INVALID) {
        ev->l3_proto = BPF_CORE_READ(skb, protocol);
        ev->l3_proto = bpf_ntohs(ev->l3_proto);
        if(!network_header || !ev->l3_proto)
            return -1;

        FILTER_EQ(ev->l3_proto, opt->l3_proto);

        pos = head + network_header;
        return match_l3(pos, opt, ev);
    }

    if(mac_header >= network_header)
        return -1;

    pos = head + mac_header;
    return match_l2(pos, opt, ev);
}

static __always_inline int trace(struct trace_context* ctx)
{
    struct sk_buff* skb = ctx->skb;
    struct option* opt = ctx->opt;
    struct event* ev = ctx->ev;
    int rc = 0;

    rc = match_skb_meta(skb, opt, ev);
    if(rc) {
        goto discard;
    }
    rc = match_skb_headers(skb, opt, ev);
    if(rc) {
        goto discard;
    }
    if(!rl_allow(opt, ev)) {
        goto discard;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;

discard:
    bpf_ringbuf_discard(ev, 0);
    return 0;
}

SEC("tracepoint/skb/kfree_skb")
int trace_skb(struct trace_event_raw_kfree_skb* raw)
{
    struct trace_context ctx = { 0 };

    ctx.opt = bpf_map_lookup_elem(&options, &(u32){ 0 });
    if(!ctx.opt) {
        return 0;
    }

    ctx.ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if(!ctx.ev) {
        return 0;
    }

    ctx.skb = raw->skbaddr;
    ctx.ev->reason = raw->reason;
    ctx.ev->location = (u64)raw->location;
    ctx.ev->timestamp = bpf_ktime_get_ns();

    return trace(&ctx);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";