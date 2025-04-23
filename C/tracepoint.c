#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

struct option {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct event {
    u8 symbol[64];
    u64 skb_ptr;
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 finish;
};

struct skb_context {
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

static __always_inline int parse_l3(struct sk_buff* skb, struct skb_context* skb_ctx)
{
    switch(bpf_ntohs(skb_ctx->eth.h_proto)) {
    case ETH_P_IP: return parse_ipv4(skb, skb_ctx);
    default: return -1;
    }
}

static __always_inline int parse_l2(struct sk_buff* skb, struct skb_context* skb_ctx)
{
    unsigned char* head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    bpf_probe_read(&skb_ctx->eth, sizeof(struct ethhdr), head + mac_header);
    return parse_l3(skb, skb_ctx);
}

static __always_inline int parse_skb(struct sk_buff* skb, struct skb_context* skb_ctx)
{
    return parse_l2(skb, skb_ctx);
}

static __always_inline int filter_by_option(struct skb_context* skb_ctx)
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

static __always_inline int
submit_event(char* symbol, u8 finish, struct sk_buff* skb, struct skb_context* skb_ctx)
{
    struct event* ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if(!ev) {
        return -1;
    }

    bpf_probe_read_str(ev->symbol, sizeof(ev->symbol), symbol);

    ev->skb_ptr = (u64)skb;
    ev->proto = skb_ctx->ip.protocol;
    ev->saddr = skb_ctx->ip.saddr;
    ev->daddr = skb_ctx->ip.daddr;
    ev->sport = 0;
    ev->dport = 0;
    ev->finish = finish;

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("kprobe/ip_rcv_core")
int BPF_KPROBE(ip_rcv_core, struct sk_buff* skb, struct net* net)
{
    struct skb_context skb_ctx = { 0 };

    if(parse_skb(skb, &skb_ctx)) {
        return 0;
    }

    if(filter_by_option(&skb_ctx)) {
        return 0;
    }

    return submit_event("ip_rcv_core", 1, skb, &skb_ctx);
}

SEC("tp_btf/netif_receive_skb")
int BPF_PROG(netif_receive_skb, struct sk_buff* skb)
{
    struct skb_context skb_ctx = { 0 };

    if(parse_skb(skb, &skb_ctx)) {
        return 0;
    }

    if(filter_by_option(&skb_ctx)) {
        return 0;
    }

    return submit_event("netif_receive_skb", 0, skb, &skb_ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";