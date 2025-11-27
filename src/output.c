#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dropreason.h"
#include "kallsyms.h"
#include "output.h"

#define COLOR_RESET "\033[0m"
#define COLOR_BOLD "\033[1m"
#define COLOR_BLACK "\033[90m"
#define COLOR_RED "\033[91m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[95m"
#define COLOR_CYAN "\033[36m"

typedef int (*print_fn)(char* buf, int length, struct event* e);

int print_dev(char* buf, int length, struct event* e);
int print_length(char* buf, int length, struct event* e);
int print_mac(char* buf, int length, struct event* e);
int print_vlan(char* buf, int length, struct event* e);
int print_l3_protocol(char* buf, int length, struct event* e);
int print_ip(char* buf, int length, struct event* e);
int print_l4_protocol(char* buf, int length, struct event* e);
int print_port(char* buf, int length, struct event* e);
int print_reason(char* buf, int length, struct event* e);
int print_location(char* buf, int length, struct event* e);

static print_fn print_fns[] = {
    print_dev,
    print_length,
    print_mac,
    print_vlan,
    print_l3_protocol,
    print_ip,
    print_l4_protocol,
    print_port,
    print_reason,
    print_location,
};

static bool color_enabled = false;

struct format_strings {
    const char* dev_fmt;
    const char* length_fmt;
    const char* mac_fmt;
    const char* vlan_fmt;
    const char* ip_fmt;
    const char* port_fmt;
    const char* reason_fmt;
    const char* location_fmt;
};

static struct format_strings fmt_color = {
    .dev_fmt = "\033[90mdev\033[0m \033[36m%s\033[0m",
    .length_fmt = "\033[90mlength\033[0m \033[33m%u\033[0m",
    .mac_fmt =
    "\033[90mmac\033[0m \033[34m%02x:%02x:%02x:%02x:%02x:%02x\033[0m > "
    "\033[34m%02x:%02x:%02x:%02x:%02x:%02x\033[0m",
    .vlan_fmt = "\033[90mvlan\033[0m \033[95m%u\033[0m \033[90mpri\033[0m "
                "\033[95m%u\033[0m",
    .ip_fmt = "\033[32m%s\033[0m > \033[32m%s\033[0m",
    .port_fmt = "\033[33m%u\033[0m > \033[33m%u\033[0m",
    .reason_fmt = "\033[90mreason\033[0m \033[1m\033[91m%s\033[0m",
    .location_fmt = "\033[90mlocation\033[0m \033[1m\033[95m%s\033[0m",
};

static struct format_strings fmt_plain = {
    .dev_fmt = "dev %s",
    .length_fmt = "length %u",
    .mac_fmt =
    "mac %02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x",
    .vlan_fmt = "vlan %u pri %u",
    .ip_fmt = "%s > %s",
    .port_fmt = "%u > %u",
    .reason_fmt = "reason %s",
    .location_fmt = "location %s",
};

static struct format_strings* fmt = &fmt_plain;

static void init_color_support(void)
{
    static bool initialized = false;
    if(initialized) {
        return;
    }
    initialized = true;

    if(!isatty(STDOUT_FILENO)) {
        color_enabled = false;
        fmt = &fmt_plain;
        return;
    }

    const char* term = getenv("TERM");
    const char* no_color = getenv("NO_COLOR");

    if(no_color != NULL && no_color[0] != '\0') {
        color_enabled = false;
        fmt = &fmt_plain;
        return;
    }

    if(term != NULL &&
    (strstr(term, "color") != NULL || strstr(term, "xterm") != NULL ||
    strstr(term, "screen") != NULL || strstr(term, "tmux") != NULL ||
    strcmp(term, "linux") == 0)) {
        color_enabled = true;
        fmt = &fmt_color;
    } else {
        fmt = &fmt_plain;
    }
}

void print_event(struct event* e)
{
    char buf[1024] = { 0 };
    int length = sizeof(buf);
    int offset = 0;

    init_color_support();

    for(int i = 0; i < sizeof(print_fns) / sizeof(print_fn); i++) {
        print_fn fn;
        int n;

        fn = print_fns[i];

        n = fn(buf + offset, length - offset, e);
        if(n < 0) {
            continue;
        }
        offset += n;

        buf[offset++] = ' ';
    }
    buf[offset - 1] = '\0';

    printf("%s\n", buf);
}

int print_dev(char* buf, int length, struct event* e)
{
    char* dev;
    int n;

    if(e->iface[0]) {
        dev = (char*)(e->iface);
    } else {
        dev = "unknown";
    }

    n = snprintf(buf, length, fmt->dev_fmt, dev);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_length(char* buf, int length, struct event* e)
{
    int n;

    n = snprintf(buf, length, fmt->length_fmt, e->length);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_mac(char* buf, int length, struct event* e)
{
    int n;

    n = snprintf(buf, length, fmt->mac_fmt, e->src_mac[0], e->src_mac[1],
    e->src_mac[2], e->src_mac[3], e->src_mac[4], e->src_mac[5], e->dst_mac[0],
    e->dst_mac[1], e->dst_mac[2], e->dst_mac[3], e->dst_mac[4], e->dst_mac[5]);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_vlan(char* buf, int length, struct event* e)
{
    int n;

    n = snprintf(buf, length, fmt->vlan_fmt, e->vlan_id, e->vlan_prio);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_l3_protocol(char* buf, int length, struct event* e)
{
    int n;

    if(e->l3_proto == 0x0800) {
        n = snprintf(buf, length, color_enabled ? "\033[96mIP\033[0m" : "IP");
    } else if(e->l3_proto == 0x86dd) {
        n = snprintf(buf, length, color_enabled ? "\033[96mIPv6\033[0m" : "IPv6");
    } else {
        n = snprintf(buf, length,
        color_enabled ? "\033[96mproto 0x%x\033[0m" : "proto 0x%x", e->l3_proto);
    }

    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_ip(char* buf, int length, struct event* e)
{
    char src[INET6_ADDRSTRLEN] = { 0 };
    char dst[INET6_ADDRSTRLEN] = { 0 };
    int n;

    if(e->l3_proto == 0x0800) {
        inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
        inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));
    } else if(e->l3_proto == 0x86dd) {
        inet_ntop(AF_INET6, &e->src_ipv6, src, sizeof(src));
        inet_ntop(AF_INET6, &e->dst_ipv6, dst, sizeof(dst));
    } else {
        return -1;
    }

    n = snprintf(buf, length, fmt->ip_fmt, src, dst);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_l4_protocol(char* buf, int length, struct event* e)
{
    int n;

    if(e->l4_proto == 6) {
        n = snprintf(buf, length, color_enabled ? "\033[94mTCP\033[0m" : "TCP");
    } else if(e->l4_proto == 17) {
        n = snprintf(buf, length, color_enabled ? "\033[94mUDP\033[0m" : "UDP");
    } else if(e->l4_proto == 1) {
        n = snprintf(buf, length, color_enabled ? "\033[94mICMP\033[0m" : "ICMP");
    } else if(e->l4_proto == 58) {
        n = snprintf(buf, length, color_enabled ? "\033[94mICMPv6\033[0m" : "ICMPv6");
    } else {
        return -1;
    }

    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_port(char* buf, int length, struct event* e)
{
    int n;

    if(e->l4_proto != 6 && e->l4_proto != 17) {
        return -1;
    }

    n = snprintf(buf, length, fmt->port_fmt, e->src_port, e->dst_port);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_reason(char* buf, int length, struct event* e)
{
    char* reason;
    int n;

    reason = get_drop_reason(e->reason);

    if(reason) {
        n = snprintf(buf, length, fmt->reason_fmt, reason);
    } else {
        const char* fmt_str =
        color_enabled ? "\033[90mreason\033[0m \033[1m\033[91m%d\033[0m" : "reason %d";
        n = snprintf(buf, length, fmt_str, e->reason);
    }

    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_location(char* buf, int length, struct event* e)
{
    struct loc_result location = { 0 };
    int n;

    lookup_kas_sym((void*)e->location, &location);

    if(location.symbol) {
        n = snprintf(buf, length, fmt->location_fmt, location.symbol);
    } else {
        const char* fmt_str = color_enabled ?
        "\033[90mlocation\033[0m \033[1m\033[95m0x%lx\033[0m" :
        "location 0x%lx";
        n = snprintf(buf, length, fmt_str, e->location);
    }

    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}