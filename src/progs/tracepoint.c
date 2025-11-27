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

#define SKB_MAC_HEADER_INVALID ((u16)~0U)

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

static __always_inline int parse_l4(void* pos, struct option* opt, struct event* ev)
{
    switch(ev->l4_proto) {
    case 6: {
        struct tcphdr tcph;
        bpf_probe_read_kernel(&tcph, sizeof(tcph), pos);

        ev->src_port = bpf_ntohs(tcph.source);
        if(opt->src_port && ev->src_port != opt->src_port) {
            return -1;
        }
        ev->dst_port = bpf_ntohs(tcph.dest);
        if(opt->dst_port && ev->dst_port != opt->dst_port) {
            return -1;
        }

        break;
    }
    case 17: {
        struct udphdr udph;
        bpf_probe_read_kernel(&udph, sizeof(udph), pos);

        ev->src_port = bpf_ntohs(udph.source);
        if(opt->src_port && ev->src_port != opt->src_port) {
            return -1;
        }
        ev->dst_port = bpf_ntohs(udph.dest);
        if(opt->dst_port && ev->dst_port != opt->dst_port) {
            return -1;
        }

        break;
    }
    case 1:
    case 58:
    default: break;
    }

    return 0;
}

static __always_inline int parse_l3(void* pos, struct option* opt, struct event* ev)
{
    switch(ev->l3_proto) {
    case 0x0800: {
        struct iphdr iph;
        bpf_probe_read_kernel(&iph, sizeof(iph), pos);
        ev->l4_proto = iph.protocol;

        ev->src_ip = iph.saddr;
        if(opt->src_ip && ev->src_ip != opt->src_ip) {
            return -1;
        }
        ev->dst_ip = iph.daddr;
        if(opt->dst_ip && ev->dst_ip != opt->dst_ip) {
            return -1;
        }

        pos += iph.ihl * 4;
        break;
    }
    case 0x86dd: {
        struct ipv6hdr ip6h;
        bpf_probe_read_kernel(&ip6h, sizeof(ip6h), pos);
        ev->l4_proto = ip6h.nexthdr;

        memcpy(ev->src_ipv6, ip6h.saddr.in6_u.u6_addr8, sizeof(ip6h.saddr));
        if(opt->src_ipv6_filter) {
            int cmp = memcmp(ev->src_ipv6, opt->src_ipv6, sizeof(opt->src_ipv6));
            if(cmp != 0) {
                return -1;
            }
        }
        memcpy(ev->dst_ipv6, ip6h.daddr.in6_u.u6_addr8, sizeof(ip6h.daddr));
        if(opt->dst_ipv6_filter) {
            int cmp = memcmp(ev->dst_ipv6, opt->dst_ipv6, sizeof(opt->dst_ipv6));
            if(cmp != 0) {
                return -1;
            }
        }

        pos += sizeof(ip6h);
        break;
    }
    default: return 0;
    }

    if(opt->l4_proto && ev->l4_proto != opt->l4_proto) {
        return -1;
    }

    return parse_l4(pos, opt, ev);
}

static __always_inline int parse_l2(void* pos, struct option* opt, struct event* ev)
{
    struct ethhdr eth;

    bpf_probe_read_kernel(&eth, sizeof(eth), pos);

    memcpy(ev->dst_mac, eth.h_dest, sizeof(eth.h_dest));
    if(opt->dst_mac_filter) {
        int cmp = memcmp(ev->dst_mac, opt->dst_mac, sizeof(opt->dst_mac));
        if(cmp != 0) {
            return -1;
        }
    }
    memcpy(ev->src_mac, eth.h_source, sizeof(eth.h_source));
    if(opt->src_mac_filter) {
        int cmp = memcmp(ev->src_mac, opt->src_mac, sizeof(opt->src_mac));
        if(cmp != 0) {
            return -1;
        }
    }

    pos += sizeof(eth);

    ev->l3_proto = bpf_ntohs(eth.h_proto);
    if(ev->l3_proto == ETH_P_8021Q || ev->l3_proto == ETH_P_8021AD) {
        struct vlan_hdr vh;
        bpf_probe_read_kernel(&vh, sizeof(vh), pos);

        u16 tci = bpf_ntohs(vh.h_vlan_TCI);
        ev->vlan_id = tci & VLAN_VID_MASK;
        ev->vlan_prio = (tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
        ev->l3_proto = bpf_ntohs(vh.h_vlan_encapsulated_proto);
        pos += sizeof(vh);
    }

    if(opt->vlan_id && ev->vlan_id != opt->vlan_id) {
        return -1;
    }
    if(opt->vlan_prio && ev->vlan_prio != opt->vlan_prio) {
        return -1;
    }
    if(opt->l3_proto && ev->l3_proto != opt->l3_proto) {
        return -1;
    }

    return parse_l3(pos, opt, ev);
}

static __always_inline int parse(struct sk_buff* skb, struct option* opt, struct event* ev)
{
    struct net_device* dev;
    u16 mac_header;
    u16 network_header;
    void *head, *pos;

    dev = BPF_CORE_READ(skb, dev);
    bpf_probe_read_kernel_str(ev->iface, sizeof(ev->iface), dev->name);
    if(opt->iface[0]) {
        int cmp = memcmp(ev->iface, opt->iface, sizeof(opt->iface));
        if(cmp != 0) {
            return -1;
        }
    }

    ev->length = BPF_CORE_READ(skb, len);
    if(opt->length && ev->length != opt->length) {
        return -1;
    }

    head = BPF_CORE_READ(skb, head);
    mac_header = BPF_CORE_READ(skb, mac_header);
    network_header = BPF_CORE_READ(skb, network_header);

    if(!mac_header || mac_header == SKB_MAC_HEADER_INVALID) {
        if(!network_header) {
            return -1;
        }
        ev->l3_proto = BPF_CORE_READ(skb, protocol);
        if(!ev->l3_proto) {
            return -1;
        }
        pos = head + network_header;
        return parse_l3(pos, opt, ev);
    } else if(mac_header && mac_header >= network_header) {
        return -1;
    } else {
        pos = head + mac_header;
        return parse_l2(pos, opt, ev);
    }
}

static __always_inline int trace(struct sk_buff* skb, struct option* opt, struct event* ev)
{
    int rc = parse(skb, opt, ev);
    if(rc != 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/skb/kfree_skb")
int trace_skb(struct trace_event_raw_kfree_skb* ctx)
{
    struct sk_buff* skb = ctx->skbaddr;
    struct option* opt;
    struct event* ev;

    opt = bpf_map_lookup_elem(&options, &(u32){ 0 });
    if(!opt) {
        return 0;
    }

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if(!ev) {
        return 0;
    }

    ev->reason = ctx->reason;
    ev->location = (u64)ctx->location;

    return trace(skb, opt, ev);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";