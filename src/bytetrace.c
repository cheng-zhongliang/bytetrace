#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "argparse.h"
#include "bytetrace.h"
#include "log.h"

static volatile sig_atomic_t g_running = 1;

static int set_log_level(struct argparse* self, const struct argparse_option* option)
{
    (void)self;

    int level = *(int*)option->value;
    switch(level) {
    case 0: level = LOG_TRACE; break;
    case 1: level = LOG_DEBUG; break;
    case 2: level = LOG_INFO; break;
    case 3: level = LOG_WARN; break;
    case 4: level = LOG_ERROR; break;
    case 5: level = LOG_FATAL; break;
    default: return -2;
    }

    log_set_level(level);
    log_set_quiet(false);

    return 0;
}

static int print_version(struct argparse* self, const struct argparse_option* option)
{
    (void)self;
    (void)option;

    printf("version: %s\n", BYTETRACE_VERSION);
    exit(0);

    return 0;
}

static int parse_args(int argc, char** argv)
{
    int log_level;

    struct argparse_option options[] = {
        OPT_GROUP("Basic options"),
        OPT_INTEGER('l', "log-level", &log_level, "set log level (0-5)", set_log_level, 0, 0),
        OPT_BOOLEAN('v', "version", NULL, "show version information and exit",
        print_version, 0, OPT_NONEG),
        OPT_HELP(),
        OPT_END(),
    };

    struct argparse argparse;
    int rc;
    argparse_init(&argparse, options, NULL, 0);
    argparse_describe(&argparse, BYTETRACE_DESCRIPTION, BYTETRACE_EPILOG);
    rc = argparse_parse(&argparse, argc, (const char**)argv);
    if(rc < 0) {
        return -1;
    }

    return 0;
}

static void sig_handler(int sig)
{
    (void)sig;

    g_running = 0;
}

int main(int argc, char** argv)
{
    int rc;

    log_set_quiet(true);

    rc = parse_args(argc, argv);
    if(rc != 0) {
        return -1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    log_info("Tracing... Press Ctrl+C to stop.");

    while(g_running) {
        sleep(1);
    }

    log_info("Bye!");

    return 0;
}
