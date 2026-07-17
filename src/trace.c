#include "trace.h"

struct trace_context {
    unsigned char unused;
};

static struct trace_context g_context;

struct trace_context* trace_context_new(const struct trace_config* config,
                                        trace_event_callback cb,
                                        void* data)
{
    (void)config;
    (void)cb;
    (void)data;

    return &g_context;
}

void trace_context_free(struct trace_context* ctx)
{
    (void)ctx;
}

int trace_context_dispatch(struct trace_context* ctx, int timeout_ms)
{
    (void)ctx;
    (void)timeout_ms;

    return 0;
}
