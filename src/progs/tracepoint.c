#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "share.h"

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

SEC("tracepoint/skb/kfree_skb")
int trace_skb(struct trace_event_raw_kfree_skb* raw_ctx) {
    struct option* opt;
    struct event* ev;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if(!ev) {
        return 0;
    }

    opt = bpf_map_lookup_elem(&options, &(u32){ 0 });
    if(!opt) {
        return 0;
    }

    ev->reason = raw_ctx->reason;
    ev->location = (u64)raw_ctx->location;

    // some test data
    __builtin_memcpy(ev->iface, "eth0", 5);
    ev->length = 1280;
    ev->vlan_id = 1;
    ev->vlan_prio = 4;
    // mac
    __builtin_memcpy(ev->src_mac, (u8[]){ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 }, 6);
    __builtin_memcpy(ev->dst_mac, (u8[]){ 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 }, 6);
    // ip
    ev->l3_proto = 0x0800;
    ev->src_ip = 0xc0a80001;
    ev->dst_ip = 0xc0a80002;
    ev->l4_proto = 6; // TCP
    ev->src_port = 12345;
    ev->dst_port = 80;

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";