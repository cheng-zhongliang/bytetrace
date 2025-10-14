<p align="center">
<img 
    src="logo.png" 
    width="350" height="175" border="0" alt="bytetrace">
<br><br>
<a title="License" target="_blank" href="https://github.com/cheng-zhongliang/bytetrace/blob/master/LICENSE"><img src="https://img.shields.io/github/license/cheng-zhongliang/bytetrace?style=flat-square"></a>
</p>

`bytetrace` is a light-weight dynamic tracer for linux packet drops. It helps you to locate the kernel function and reason for packet drops in a simple and efficient way.

> [!NOTE]
> IPV6 is supported.

## Features

- Locate kernel packet drop reason and function
- Filter by interface, protocol, ip, port, etc.
- ~~Dump packet drop call stack~~
- Cross-platform support (Linux)
- Easy to use and deploy

## Getting Started

### Installing

To start using `bytetrace`, just run the following command:

```sh
$ git clone https://github.com/cheng-zhongliang/bytetrace.git
$ cd bytetrace/src
$ make
```

### Usage

```
$ ./bytetrace -h
Light-weight Dynamic Tracer for Linux Network Stack

Basic options
    -b, --btf=<str>           set BTF path
    -l, --log-level=<int>     set log level (0-4)
    -v, --version             show version information and exit
    -h, --help                show this help message and exit

Filter options
    --iface=<str>             set interface filter
    --length=<int>            set packet length filter
    --src-mac=<str>           set source MAC filter
    --dst-mac=<str>           set destination MAC filter
    --vlan-id=<int>           set VLAN ID filter
    --vlan-prio=<int>         set VLAN priority filter
    --l3-proto=<str>          set L3 protocol filter
    --src-ip=<str>            set source IP filter
    --dst-ip=<str>            set destination IP filter
    --src-ipv6=<str>          set source IPv6 filter
    --dst-ipv6=<str>          set destination IPv6 filter
    --l4-proto=<str>          set L4 protocol filter
    --src-port=<int>          set source port filter
    --dst-port=<int>          set destination port filter

Report bugs to <cheng.zhongliang@h3c.com>
```

### Example

Trace icmp packet drops on interface `ens1f0np0`:

```sh
$ bytetrace --iface=ens1f0np0 --l4-proto=icmp
```

Output:

```
dev ens1f0np0 length 84 mac 55:55:aa:00:12:02 > 09:10:87:3e:2d:3b vlan 0 pri 0 IP 39.156.70.37 > 10.0.2.15 ICMP reason NETFILTER_DROP location nft_do_chain
```
