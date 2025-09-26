#include <signal.h>
#include <stdlib.h>

#include "argparse.h"
#include "bytetrace.h"
#include "trace.h"
#include "vlog.h"

#define LOG_MODULE VLM_bytetrace

static int g_running = 1;

static void sig_handler(int sig) {
    if(sig == SIGINT || sig == SIGTERM) {
        g_running = 0;
    }
}

static const char* description =
"Light-weight Dynamic Tracer for Linux Packet Drop";

static int set_log_level(struct argparse* self, const struct argparse_option* option) {
    struct trace_context* ctx = (struct trace_context*)option->data;
    vlog_set_levels(VLM_ANY_MODULE, VLF_ANY_FACILITY, ctx->log_level);
    return 0;
}

static int print_version(struct argparse* self, const struct argparse_option* option) {
    printf("version: %s\n", BYTETRACE_VERSION);
    exit(0);
    return 0;
}


int parse_args(struct trace_context* ctx, int argc, char** argv) {
    struct argparse_option options[] = {
        OPT_GROUP("Basic options"),
        OPT_INTEGER('l', "log-level", &ctx->log_level, "set log level (0-4)",
        set_log_level, (intptr_t)ctx, 0),
        OPT_BOOLEAN('v', "version", NULL,
        "display version information and exit", print_version, 0, OPT_NONEG),
        OPT_HELP(),
        OPT_GROUP("Filter options"),
        OPT_INTEGER('\0', "l3-proto", &ctx->opt->l3_proto,
        "set L3 protocol filter", NULL, 0, 0),
        OPT_INTEGER('\0', "l4-proto", &ctx->opt->l4_proto,
        "set L4 protocol filter", NULL, 0, 0),
        OPT_INTEGER('\0', "src-ip", &ctx->opt->src_ip, "set source IP filter", NULL, 0, 0),
        OPT_INTEGER('\0', "dst-ip", &ctx->opt->dst_ip,
        "set destination IP filter", NULL, 0, 0),
        OPT_INTEGER('\0', "src-port", &ctx->opt->src_port,
        "set source port filter", NULL, 0, 0),
        OPT_INTEGER('\0', "dst-port", &ctx->opt->dst_port,
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
    struct trace_context ctx;
    int rc;

    vlog_set_levels(VLM_ANY_MODULE, VLF_ANY_FACILITY, VLL_ERR);

    rc = parse_args(&ctx, argc, argv);
    if(rc != 0) {
        return -1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    return 0;
}