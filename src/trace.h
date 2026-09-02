#ifndef TRACE_H
#define TRACE_H

#include <stdbool.h>
#include <stdint.h>

struct trace_context;

/*
 * Creates a context with rate limiting and all filters disabled.
 * Returns NULL if memory allocation fails.
 */
struct trace_context* trace_context_new(void);

/* Setters must be called before trace_context_attach(). */
/* path must remain valid until trace_context_free() is called. */
int trace_context_set_btf_path(struct trace_context* ctx, const char* path);
int trace_context_set_ratelimit(struct trace_context* ctx, bool enabled);
/* iface must remain valid until trace_context_free() is called. */
int trace_context_set_filter_iface(struct trace_context* ctx, const char* iface);
int trace_context_set_filter_packet_len(struct trace_context* ctx, uint32_t length);
int trace_context_set_filter_src_mac(struct trace_context* ctx, const char* address);
int trace_context_set_filter_dst_mac(struct trace_context* ctx, const char* address);
int trace_context_set_filter_vlan_id(struct trace_context* ctx, uint16_t vlan_id);
int trace_context_set_filter_vlan_prio(struct trace_context* ctx, uint8_t priority);
int trace_context_set_filter_eth_proto(struct trace_context* ctx, uint16_t protocol);
int trace_context_set_filter_src_ip(struct trace_context* ctx, const char* address);
int trace_context_set_filter_dst_ip(struct trace_context* ctx, const char* address);
int trace_context_set_filter_ip_proto(struct trace_context* ctx, uint8_t protocol);
int trace_context_set_filter_src_port(struct trace_context* ctx, uint16_t port);
int trace_context_set_filter_dst_port(struct trace_context* ctx, uint16_t port);

int trace_context_attach(struct trace_context* ctx);

/*
 * Returns the number of processed events, 0 on timeout, or a negative value
 * on error.
 */
int trace_context_dispatch(struct trace_context* ctx, int timeout_ms);

/* Detaches tracing resources and accepts NULL. */
void trace_context_free(struct trace_context* ctx);

#endif
