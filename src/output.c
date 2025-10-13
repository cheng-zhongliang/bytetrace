#include <arpa/inet.h>
#include <stdio.h>

#include "dropreason.h"
#include "kallsyms.h"
#include "output.h"

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

void print_event(struct event* e)
{
    char buf[1024] = { 0 };
    int length = sizeof(buf);
    int offset = 0;

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

    n = snprintf(buf, length, "dev %s", dev);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_length(char* buf, int length, struct event* e)
{
    int n;

    n = snprintf(buf, length, "length %u", e->length);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_mac(char* buf, int length, struct event* e)
{
    int n;

    n = snprintf(buf, length, "mac %02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x",
    e->src_mac[0], e->src_mac[1], e->src_mac[2], e->src_mac[3], e->src_mac[4],
    e->src_mac[5], e->dst_mac[0], e->dst_mac[1], e->dst_mac[2], e->dst_mac[3],
    e->dst_mac[4], e->dst_mac[5]);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_vlan(char* buf, int length, struct event* e)
{
    int n;

    n = snprintf(buf, length, "vlan %u pri %u", e->vlan_id, e->vlan_prio);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_l3_protocol(char* buf, int length, struct event* e)
{
    int n;

    if(e->l3_proto == 0x0800) {
        n = snprintf(buf, length, "IP");
    } else if(e->l3_proto == 0x86dd) {
        n = snprintf(buf, length, "IPv6");
    } else {
        n = snprintf(buf, length, "proto 0x%x", e->l3_proto);
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

    n = snprintf(buf, length, "%s > %s", src, dst);
    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}

int print_l4_protocol(char* buf, int length, struct event* e)
{
    int n;

    if(e->l4_proto == 6) {
        n = snprintf(buf, length, "TCP");
    } else if(e->l4_proto == 17) {
        n = snprintf(buf, length, "UDP");
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

    n = snprintf(buf, length, "%u > %u", e->src_port, e->dst_port);
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
        n = snprintf(buf, length, "reason %s", reason);
    } else {
        n = snprintf(buf, length, "reason %d", e->reason);
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
        n = snprintf(buf, length, "location %s", location.symbol);
    } else {
        n = snprintf(buf, length, "location 0x%lx", e->location);
    }

    if(n < 0 || n >= length) {
        return -1;
    }

    return n;
}