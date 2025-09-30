#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "argparse.h"
#include "bytetrace.h"
#include "proto.h"
#include "trace.h"
#include "vlog.h"

#define LOG_MODULE VLM_bytetrace

static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static const char* description =
"Light-weight Dynamic Tracer for Linux Network Stack";

static int set_log_level(struct argparse* self, const struct argparse_option* option) {
    int level = *(int*)option->value;
    switch(level) {
    case 0: level = VLL_DBG; break;
    case 1: level = VLL_INFO; break;
    case 2: level = VLL_WARN; break;
    case 3: level = VLL_ERR; break;
    case 4: level = VLL_EMER; break;
    default: return -2;
    }
    vlog_set_levels(VLM_ANY_MODULE, VLF_ANY_FACILITY, level);
    return 0;
}

static int print_version(struct argparse* self, const struct argparse_option* option) {
    printf("version: %s\n", BYTETRACE_VERSION);
    exit(0);
    return 0;
}

static int parse_iface(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    char* iface = *(char**)option->value;
    memcpy(ctx->opt.iface, iface, 16);
    return 0;
}

static int parse_src_ip(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    char* ip = *(char**)option->value;
    int rc;
    rc = inet_pton(AF_INET, ip, &ctx->opt.src_ip);
    if(rc <= 0) {
        return -2;
    }
    return 0;
}

static int parse_dst_ip(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    char* ip = *(char**)option->value;
    int rc;
    rc = inet_pton(AF_INET, ip, &ctx->opt.dst_ip);
    if(rc <= 0) {
        return -2;
    }
    return 0;
}

static int parse_src_ip6(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    char* ip = *(char**)option->value;
    int rc;
    rc = inet_pton(AF_INET6, ip, &ctx->opt.src_ipv6);
    if(rc <= 0) {
        return -2;
    }
    return 0;
}

static int parse_dst_ip6(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    char* ip = *(char**)option->value;
    int rc;
    rc = inet_pton(AF_INET6, ip, &ctx->opt.dst_ipv6);
    if(rc <= 0) {
        return -2;
    }
    return 0;
}

static int parse_src_mac(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    char* mac = *(char**)option->value;
    int rc;
    rc = sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ctx->opt.src_mac[0],
    &ctx->opt.src_mac[1], &ctx->opt.src_mac[2], &ctx->opt.src_mac[3],
    &ctx->opt.src_mac[4], &ctx->opt.src_mac[5]);
    if(rc != 6) {
        return -2;
    }
    return 0;
}

static int parse_dst_mac(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    char* mac = *(char**)option->value;
    int rc;
    rc = sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ctx->opt.dst_mac[0],
    &ctx->opt.dst_mac[1], &ctx->opt.dst_mac[2], &ctx->opt.dst_mac[3],
    &ctx->opt.dst_mac[4], &ctx->opt.dst_mac[5]);
    if(rc != 6) {
        return -2;
    }
    return 0;
}

static int parse_l3_proto(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    char* proto = *(char**)option->value;
    int rc;
    rc = proto2i(proto, (int*)(&ctx->opt.l3_proto));
    if(rc == 0) {
        return -2;
    }
    return 0;
}

static int parse_l4_proto(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    char* proto = *(char**)option->value;
    int rc;
    rc = proto2i(proto, (int*)(&ctx->opt.l4_proto));
    if(rc == 0) {
        return -2;
    }
    return 0;
}

int parse_args(struct trace_context* ctx, int argc, char** argv) {
    int log_level;
    char* iface;
    char* src_mac;
    char* dst_mac;
    char* src_ip;
    char* dst_ip;
    char* l3_proto;
    char* l4_proto;

    struct argparse_option options[] = {
        OPT_GROUP("Basic options"),
        OPT_STRING('b', "btf", &ctx->btf_path, "set BTF path", NULL, 0, 0),
        OPT_INTEGER('l', "log-level", &log_level, "set log level (0-4)", set_log_level, 0, 0),
        OPT_BOOLEAN('v', "version", NULL, "show version information and exit",
        print_version, 0, OPT_NONEG),
        OPT_HELP(),
        OPT_GROUP("Filter options"),
        OPT_STRING('\0', "iface", &iface, "set interface filter", parse_iface,
        (intptr_t)ctx, 0),
        OPT_INTEGER('\0', "length", &ctx->opt.length, "set packet length filter", NULL, 0, 0),
        OPT_STRING('\0', "src-mac", &src_mac, "set source MAC filter",
        parse_src_mac, (intptr_t)ctx, 0),
        OPT_STRING('\0', "dst-mac", &dst_mac, "set destination MAC filter",
        parse_dst_mac, (intptr_t)ctx, 0),
        OPT_INTEGER('\0', "vlan-id", &ctx->opt.vlan_id, "set VLAN ID filter", NULL, 0, 0),
        OPT_INTEGER('\0', "vlan-prio", &ctx->opt.vlan_prio,
        "set VLAN priority filter", NULL, 0, 0),
        OPT_STRING('\0', "l3-proto", &l3_proto, "set L3 protocol filter",
        parse_l3_proto, (intptr_t)ctx, 0),
        OPT_STRING('\0', "src-ip", &src_ip, "set source IP filter",
        parse_src_ip, (intptr_t)ctx, 0),
        OPT_STRING('\0', "dst-ip", &dst_ip, "set destination IP filter",
        parse_dst_ip, (intptr_t)ctx, 0),
        OPT_STRING('\0', "src-ipv6", &src_ip, "set source IPv6 filter",
        parse_src_ip6, (intptr_t)ctx, 0),
        OPT_STRING('\0', "dst-ipv6", &dst_ip, "set destination IPv6 filter",
        parse_dst_ip6, (intptr_t)ctx, 0),
        OPT_STRING('\0', "l4-proto", &l4_proto, "set L4 protocol filter",
        parse_l4_proto, (intptr_t)ctx, 0),
        OPT_INTEGER('\0', "src-port", &ctx->opt.src_port,
        "set source port filter", NULL, 0, 0),
        OPT_INTEGER('\0', "dst-port", &ctx->opt.dst_port,
        "set destination port filter", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    int rc;

    argparse_init(&argparse, options, NULL, 0);
    argparse_describe(&argparse, description, NULL);
    rc = argparse_parse(&argparse, argc, (const char**)argv);
    if(rc < 0) {
        return -1;
    }

    return 0;
}

int main(int argc, char** argv) {
    struct trace_context ctx = { 0 };
    int rc;

    rc = parse_args(&ctx, argc, argv);
    if(rc != 0) {
        return -1;
    }

    rc = trace_init(&ctx);
    if(rc != 0) {
        return -1;
    }

    rc = trace_attach(&ctx);
    if(rc != 0) {
        trace_deinit(&ctx);
        return -1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    VLOG_INFO(LOG_MODULE, "Tracing... Press Ctrl+C to stop.");

    while(g_running) {
        rc = trace_poll(&ctx, 100);
        if(rc < 0) {
            break;
        }
    }

    trace_detach(&ctx);
    trace_deinit(&ctx);

    VLOG_INFO(LOG_MODULE, "Bye!");

    return 0;
}