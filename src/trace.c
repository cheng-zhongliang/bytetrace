#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "log.h"
#include "output.h"
#include "share.h"
#include "trace.h"
#include "tracepoint.h"

#define LOG_MODULE VLM_trace

static int on_recv(void* ctx, void* data, size_t size) {
    struct event* e = (struct event*)data;
    print_event(e);
    return 0;
}

int setup_event_listen(struct trace_context* ctx) {
    int fd;

    fd = bpf_map__fd(ctx->events_map);

    ctx->rb = ring_buffer__new(fd, on_recv, NULL, NULL);
    if(ctx->rb == NULL) {
        log_error("Failed to open ring buffer: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int trace_init(struct trace_context* ctx) {
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = ctx->btf_path);
    int rc;

    ctx->obj = bpf_object__open_mem(tracepoint, tracepoint_len, &opts);
    if(ctx->obj == NULL) {
        log_error("Failed to open BPF object: %s", strerror(errno));
        return -1;
    }

    rc = bpf_object__load(ctx->obj);
    if(rc != 0) {
        log_error("Failed to load BPF object: %s", strerror(errno));
        bpf_object__close(ctx->obj);
        return -1;
    }

    ctx->prog = bpf_object__find_program_by_name(ctx->obj, "trace_skb");
    ctx->events_map = bpf_object__find_map_by_name(ctx->obj, "events");
    ctx->options_map = bpf_object__find_map_by_name(ctx->obj, "options");

    return setup_event_listen(ctx);
}

int trace_attach(struct trace_context* ctx) {
    int rc;

    rc = bpf_map__update_elem(ctx->options_map, &((uint32_t){ 0 }),
    sizeof(uint32_t), &ctx->opt, sizeof(ctx->opt), BPF_ANY);
    if(rc != 0) {
        log_error("Failed to update options map: %s", strerror(errno));
        return -1;
    }

    ctx->link = bpf_program__attach(ctx->prog);
    if(ctx->link == NULL) {
        log_error("Failed to attach BPF program: %s", strerror(errno));
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
    rc = ring_buffer__poll(ctx->rb, timeout_ms);
    if(rc < 0 && errno != EINTR) {
        log_error("Error polling perf buffer: %s", strerror(errno));
        return -1;
    }
    return 0;
}

void trace_deinit(struct trace_context* ctx) {
    if(ctx->rb) {
        ring_buffer__free(ctx->rb);
    }
    if(ctx->obj) {
        bpf_object__close(ctx->obj);
    }
    return;
}