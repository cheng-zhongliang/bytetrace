#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define get_drop_reason(ctx) *(int*)(void*)((u64*)(ctx) + 2)

struct option {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct event {
    u16 reason;
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct skb_context {
    u16 reason;
    struct ethhdr eth;
    struct iphdr ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(value, struct option);
    __type(key, u32);
    __uint(max_entries, 1);
} options SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} events SEC(".maps");

static __always_inline int parse_ipv4(struct sk_buff* skb, struct skb_context* skb_ctx)
{
    unsigned char* head = BPF_CORE_READ(skb, head);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    bpf_probe_read(&skb_ctx->ip, sizeof(struct iphdr), head + network_header);
    return 0;
}

static __always_inline int parse_l4(struct sk_buff* skb, struct skb_context* skb_ctx)
{
    return 0;
}

static __always_inline int parse_l3(struct sk_buff* skb, struct skb_context* skb_ctx)
{
    switch(bpf_ntohs(skb_ctx->eth.h_proto)) {
    case ETH_P_IP: {
        if(parse_ipv4(skb, skb_ctx)) {
            return -1;
        }
        break;
    };
    default: return -1;
    }
    return parse_l4(skb, skb_ctx);
}

static __always_inline int parse_l2(struct sk_buff* skb, struct skb_context* skb_ctx)
{
    unsigned char* head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    bpf_probe_read(&skb_ctx->eth, sizeof(struct ethhdr), head + mac_header);
    return parse_l3(skb, skb_ctx);
}

static __always_inline int parse(struct sk_buff* skb, struct skb_context* skb_ctx)
{
    return parse_l2(skb, skb_ctx);
}

static __always_inline int filter(struct skb_context* skb_ctx)
{
    int _key = 0;
    struct option* opt = bpf_map_lookup_elem(&options, &_key);
    if(!opt) {
        return -1;
    }

    if(opt->proto && opt->proto != skb_ctx->ip.protocol) {
        return -1;
    }

    if(opt->saddr && opt->saddr != skb_ctx->ip.saddr) {
        return -1;
    }

    if(opt->daddr && opt->daddr != skb_ctx->ip.daddr) {
        return -1;
    }

    return 0;
}

static __always_inline int submit(struct skb_context* skb_ctx)
{
    struct event e;

    e.reason = skb_ctx->reason;
    e.proto = skb_ctx->ip.protocol;
    e.saddr = skb_ctx->ip.saddr;
    e.daddr = skb_ctx->ip.daddr;
    e.sport = 0;
    e.dport = 0;

    return bpf_ringbuf_output(&events, &e, sizeof(e), 0);
}

static __always_inline int trace(void* ctx, struct sk_buff* skb, struct skb_context* skb_ctx)
{
    if(parse(skb, skb_ctx)) {
        return 0;
    }

    if(filter(skb_ctx)) {
        return 0;
    }

    return submit(skb_ctx);
}

SEC("tp_btf/kfree_skb")
int BPF_PROG(kfree_skb, struct sk_buff* skb)
{
    int reason;
    struct skb_context skb_ctx;

    if(bpf_core_type_exists(enum skb_drop_reason)) {
        reason = get_drop_reason(ctx);
    } else {
        return 0;
    }

    if(reason <= SKB_DROP_REASON_NOT_SPECIFIED) {
        return 0;
    }

    skb_ctx.reason = reason;

    return trace(ctx, skb, &skb_ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";