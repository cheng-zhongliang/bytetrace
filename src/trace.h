#ifndef __BYE_TRACE_H__
#define __BYE_TRACE_H__

#include <stdint.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"

struct trace_context {
    struct bpf_object* obj;
    struct perf_buffer* pb;
    const char* btf_path;
    struct filter_option opt;
};

int trace_init(struct trace_context* ctx);
int trace_attach(struct trace_context* ctx);
void trace_detach(struct trace_context* ctx);
int trace_poll(struct trace_context* ctx, int timeout_ms);
void trace_deinit(struct trace_context* ctx);

#endif