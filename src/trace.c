#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "trace.h"
#include "tracepoint.h"
#include "vlog.h"

#define LOG_MODULE VLM_trace

int setup_perf_buffer(struct trace_context* ctx) {
    int fd;

    fd = bpf_map__fd(ctx->events_map);

    ctx->pb = perf_buffer__new(fd, 8, NULL, NULL, ctx, NULL);
    if(!ctx->pb) {
        VLOG_ERR(LOG_MODULE, "Failed to open perf buffer: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int trace_init(struct trace_context* ctx) {
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = ctx->btf_path);
    int rc;

    ctx->obj = bpf_object__open_mem(tracepoint, tracepoint_len, &opts);
    if(!ctx->obj) {
        VLOG_ERR(LOG_MODULE, "Failed to open BPF object: %s", strerror(errno));
        return -1;
    }

    rc = bpf_object__load(ctx->obj);
    if(rc != 0) {
        VLOG_ERR(LOG_MODULE, "Failed to load BPF object: %s", strerror(errno));
        bpf_object__close(ctx->obj);
        return -1;
    }

    ctx->prog = bpf_object__find_program_by_name(ctx->obj, "trace_func");
    ctx->events_map = bpf_object__find_map_by_name(ctx->obj, "events");
    ctx->options_map = bpf_object__find_map_by_name(ctx->obj, "options");

    return setup_perf_buffer(ctx);
}

int trace_attach(struct trace_context* ctx) {
    int rc;

    rc = bpf_map__update_elem(ctx->options_map, &((uint32_t){ 0 }),
    sizeof(uint32_t), &ctx->opt, sizeof(ctx->opt), BPF_ANY);
    if(rc != 0) {
        VLOG_ERR(LOG_MODULE, "Failed to update options map: %s", strerror(errno));
        return -1;
    }

    ctx->link = bpf_program__attach(ctx->prog);
    if(!ctx->link) {
        VLOG_ERR(LOG_MODULE, "Failed to attach BPF program: %s", strerror(errno));
        return -1;
    }

    return 0;
}

void trace_detach(struct trace_context* ctx) {
    bpf_link__detach(ctx->link);
    bpf_link__destroy(ctx->link);
    return;
}

int trace_poll(struct trace_context* ctx, int timeout_ms) {
    int rc;
    rc = perf_buffer__poll(ctx->pb, timeout_ms);
    if(rc < 0) {
        VLOG_ERR(LOG_MODULE, "Error polling perf buffer: %s", strerror(errno));
        return -1;
    }
    return 0;
}

void trace_deinit(struct trace_context* ctx) {
    if(ctx->pb) {
        perf_buffer__free(ctx->pb);
    }
    if(ctx->obj) {
        bpf_object__close(ctx->obj);
    }
    return;
}