#include <arpa/inet.h>
#include <stdio.h>


#include "output.h"

// eth0 length 1280 mac 11:11:11:11:11 > 22:22:22:22:22:22 vlan 1 pri 4 IP 192.168.0.1 > 1922.168.0.2 reason NET_DROP location tcp_rcv
void print_event(struct event* e) {
    char buf[1024] = { 0 };
    int length = sizeof(buf);
    int off = 0;
    char* dev;

    // iface
    if(e->iface[0]) {
        dev = e->iface;
    } else {
        dev = "unknown";
    }
    off += snprintf(buf + off, length - off, "dev %s ", dev);
    // length
    off += snprintf(buf + off, length - off, "length %d ", e->length);
    // mac
    off += snprintf(buf + off, length - off,
    "mac %02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x ",
    e->src_mac[0], e->src_mac[1], e->src_mac[2], e->src_mac[3], e->src_mac[4],
    e->src_mac[5], e->dst_mac[0], e->dst_mac[1], e->dst_mac[2], e->dst_mac[3],
    e->dst_mac[4], e->dst_mac[5]);
    // vlan
    off += snprintf(buf + off, length - off, "vlan %d ", e->vlan_id);
    // pri
    off += snprintf(buf + off, length - off, "pri %d ", e->vlan_prio);
    // l3 proto
    switch(e->l3_proto) {
    case 0x0800:
        off += snprintf(buf + off, length - off, "IP ");
        // ip
        struct in_addr src, dst;
        src.s_addr = e->src_ip;
        dst.s_addr = e->dst_ip;
        off +=
        snprintf(buf + off, length - off, "%s > %s ", inet_ntoa(src), inet_ntoa(dst));
        // l4 proto
        break;
    case 0x86DD: off += snprintf(buf + off, length - off, "IPV6 "); break;
    case 0x0806: off += snprintf(buf + off, length - off, "ARP "); break;
    default:
        off += snprintf(buf + off, length - off, "L3_PROTO_0x%04x ", e->l3_proto);
        break;
    }
    switch(e->l4_proto) {
    case 1: off += snprintf(buf + off, length - off, "ICMP "); break;
    case 6: off += snprintf(buf + off, length - off, "TCP "); break;
    case 17: off += snprintf(buf + off, length - off, "UDP "); break;
    default:
        off += snprintf(buf + off, length - off, "L4_PROTO_%d ", e->l4_proto);
        break;
    }
    // port
    if(e->src_port && e->dst_port) {
        off += snprintf(buf + off, length - off, "%d > %d ", ntohs(e->src_port),
        ntohs(e->dst_port));
    }
    // reason
    off += snprintf(buf + off, length - off, "reason %d ", e->reason);
    // location
    off += snprintf(buf + off, length - off, "location 0x%lx ", e->location);

    printf("%s\n", buf);
}