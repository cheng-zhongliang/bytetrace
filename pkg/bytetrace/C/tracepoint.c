#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_HLEN 14

#define VLAN_TAG_PRESENT 0x1000
#define VLAN_VID_MASK 0x0FFF

typedef void* stack_trace_t[64];

static __always_inline bool eth_type_vlan(u16 ethertype)
{
    switch(ethertype) {
    case bpf_htons(ETH_P_8021Q):
    case bpf_htons(ETH_P_8021AD): return true;
    default: return false;
    }
}

static __always_inline bool skb_vlan_tag_present(u16 vlan_tci)
{
    return (vlan_tci & VLAN_TAG_PRESENT) != 0;
}

static __always_inline int strncmp(u8* s1, u8* s2, int n)
{
    for(int i = 0; i < n; i++) {
        if(s1[i] != s2[i])
            return s1[i] - s2[i];
        if(s1[i] == '\0' || s2[i] == '\0')
            break;
    }
    return 0;
}

struct option {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 vlan_id;
    bool stack;
    bool verbose;
    bool valid_reason;
    u8 dev_name[16];
};

struct event {
    u16 reason;
    u64 location;
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 vlan_id;
    u8 dev_name[16];
    u32 stack_id;
};

struct trace_context {
    u16 reason;
    u32 stack_id;
    u64 location;
    u16 sport;
    u16 dport;
    u16 vlan_id;
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    struct tcphdr tcp;
    struct net_device* dev;
    struct option* opt;
    struct trace_event_raw_kfree_skb* raw_ctx;
    struct sk_buff* skb;
    void* pos;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(value, struct option);
    __type(key, u32);
    __uint(max_entries, 1);
} options SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __type(value, struct event);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
    __type(value, stack_trace_t);
    __uint(max_entries, 0xfff);
} stacks SEC(".maps");

static __always_inline int parse_udp(struct trace_context* ctx)
{
    void* pos = ctx->pos;
    struct option* opt = ctx->opt;

    struct udphdr* udp = &ctx->udp;
    bpf_probe_read_kernel(udp, sizeof(*udp), pos);

    ctx->sport = udp->source;
    ctx->dport = udp->dest;

    if(opt->sport && opt->sport != ctx->sport) {
        return -1;
    }
    if(opt->dport && opt->dport != ctx->dport) {
        return -1;
    }

    return 0;
}

static __always_inline int parse_tcp(struct trace_context* ctx)
{
    void* pos = ctx->pos;
    struct option* opt = ctx->opt;

    struct tcphdr* tcp = &ctx->tcp;
    bpf_probe_read_kernel(tcp, sizeof(*tcp), pos);

    ctx->sport = tcp->source;
    ctx->dport = tcp->dest;

    if(opt->sport && opt->sport != ctx->sport) {
        return -1;
    }
    if(opt->dport && opt->dport != ctx->dport) {
        return -1;
    }

    return 0;
}

static __always_inline int parse_l4(struct trace_context* ctx)
{
    switch(ctx->ip.protocol) {
    case IPPROTO_UDP: return parse_udp(ctx);
    case IPPROTO_TCP: return parse_tcp(ctx);
    default: return 0;
    }
}

static __always_inline int parse_ipv4(struct trace_context* ctx)
{
    void* pos = ctx->pos;
    struct option* opt = ctx->opt;
    struct iphdr* ip = &ctx->ip;

    bpf_probe_read_kernel(ip, sizeof(*ip), pos);

    if(opt->proto && opt->proto != ip->protocol) {
        return -1;
    }
    if(opt->saddr && opt->saddr != ip->saddr) {
        return -1;
    }
    if(opt->daddr && opt->daddr != ip->daddr) {
        return -1;
    }

    ctx->pos += ctx->ip.ihl * 4;

    return 0;
}

static __always_inline int parse_l3(struct trace_context* ctx)
{
    switch(ctx->eth.h_proto) {
    case bpf_htons(ETH_P_IP): {
        if(parse_ipv4(ctx)) {
            return -1;
        }
        break;
    };
    case bpf_htons(ETH_P_IPV6):
    default: return -1;
    }

    return parse_l4(ctx);
}

static __always_inline int parse_l2(struct trace_context* ctx)
{
    struct sk_buff* skb = ctx->skb;
    struct option* opt = ctx->opt;
    struct ethhdr* eth = &ctx->eth;

    u16 proto = BPF_CORE_READ(skb, protocol);
    if(eth_type_vlan(proto)) {
        return 0;
    }

    u16 vlan_tci = BPF_CORE_READ(skb, vlan_tci);
    if(skb_vlan_tag_present(vlan_tci)) {
        u16 vlan_id = vlan_tci & VLAN_VID_MASK;
        ctx->vlan_id = vlan_id;
        if(opt->vlan_id && vlan_id != opt->vlan_id) {
            return -1;
        }
    }

    void* head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);

    ctx->pos = head + mac_header;

    bpf_probe_read_kernel(eth, sizeof(*eth), ctx->pos);

    ctx->pos += ETH_HLEN;

    return parse_l3(ctx);
}

static __always_inline int parse(struct trace_context* ctx)
{
    struct sk_buff* skb = ctx->skb;
    struct option* opt = ctx->opt;
    int reason = ctx->reason;

    if(opt->valid_reason && reason <= SKB_DROP_REASON_NOT_SPECIFIED) {
        return -1;
    }

    ctx->dev = BPF_CORE_READ(skb, dev);
    if(opt->dev_name[0]) {
        u8 name[16];
        bpf_probe_read_kernel_str(name, sizeof(name), ctx->dev->name);
        if(strncmp(name, opt->dev_name, sizeof(name))) {
            return -1;
        }
    }

    return parse_l2(ctx);
}

static __always_inline int submit(struct trace_context* ctx)
{
    struct event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e) {
        return 0;
    }

    e->reason = ctx->reason;
    e->location = ctx->location;
    e->proto = ctx->ip.protocol;
    e->saddr = bpf_ntohl(ctx->ip.saddr);
    e->daddr = bpf_ntohl(ctx->ip.daddr);
    e->sport = bpf_ntohs(ctx->sport);
    e->dport = bpf_ntohs(ctx->dport);
    e->vlan_id = ctx->vlan_id;
    e->stack_id = ctx->stack_id;
    bpf_probe_read_kernel_str(e->dev_name, sizeof(e->dev_name), ctx->dev->name);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

static __always_inline int trace(struct trace_context* ctx)
{
    struct option* opt = ctx->opt;

    if(parse(ctx)) {
        return 0;
    }

    if(opt->stack) {
        ctx->stack_id = bpf_get_stackid(ctx->raw_ctx, &stacks, 0);
    }

    return submit(ctx);
}

SEC("tracepoint/skb/kfree_skb")
int trace_skb(struct trace_event_raw_kfree_skb* raw_ctx)
{
    struct trace_context ctx = { 0 };
    struct option* opt;

    opt = bpf_map_lookup_elem(&options, &(u32){ 0 });
    if(!opt) {
        return 0;
    }

    ctx.opt = opt;
    ctx.raw_ctx = raw_ctx;
    ctx.skb = raw_ctx->skbaddr;
    ctx.reason = raw_ctx->reason;
    ctx.location = (u64)raw_ctx->location;

    return trace(&ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";