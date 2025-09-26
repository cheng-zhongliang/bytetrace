#include <stdlib.h>

#include "trace.h"

int trace_init(struct trace_context* ctx) {
    return 0;
}

int trace_attach(struct trace_context* ctx) {
    return 0;
}

void trace_detach(struct trace_context* ctx) {
    return;
}

int trace_poll(struct trace_context* ctx, int timeout_ms) {
    return 0;
}

void trace_deinit(struct trace_context* ctx) {
    if(ctx) {
        if(ctx->pb) {
            perf_buffer__free(ctx->pb);
            ctx->pb = NULL;
        }
        if(ctx->obj) {
            bpf_object__close(ctx->obj);
            ctx->obj = NULL;
        }
        free(ctx);
    }
}