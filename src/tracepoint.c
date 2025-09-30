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
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 256);
} events SEC(".maps");

SEC("tracepoint/skb/kfree_skb")
int trace_skb(struct trace_event_raw_kfree_skb* raw_ctx) {
    struct option* opt;
    struct event ev;

    opt = bpf_map_lookup_elem(&options, &(u32){ 0 });
    if(!opt) {
        return 0;
    }

    ev.reason = raw_ctx->reason;
    ev.location = (u64)raw_ctx->location;

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";