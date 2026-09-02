#include <stdlib.h>

#include "abi.h"
#include "trace.h"

struct trace_context {
    const char* btf_path;
    const char* iface;

    struct trace_config cfg;
};

struct trace_context* trace_context_new(void)
{
    struct trace_context* ctx;

    ctx = calloc(1, sizeof(*ctx));
    if(!ctx) {
        return NULL;
    }

    ctx->cfg.filters = TRACE_FILTER_NONE;
    ctx->cfg.ratelimit = false;

    return ctx;
}

int trace_context_set_btf_path(struct trace_context* ctx, const char* path)
{
    if(!ctx || !path || path[0] == '\0') {
        return -1;
    }

    ctx->btf_path = path;

    return 0;
}

int trace_context_set_ratelimit(struct trace_context* ctx, bool enabled)
{
    if(!ctx) {
        return -1;
    }

    ctx->cfg.ratelimit = enabled;

    return 0;
}

int trace_context_set_filter_iface(struct trace_context* ctx, const char* iface)
{
    if(!ctx || !iface || iface[0] == '\0') {
        return -1;
    }

    ctx->iface = iface;
    ctx->cfg.filters |= TRACE_FILTER_IFACE;

    return 0;
}
