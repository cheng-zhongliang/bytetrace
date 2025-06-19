<p align="center">
<img 
    src="logo.png" 
    width="350" height="175" border="0" alt="bytetrace">
<br><br>
<a title="License" target="_blank" href="https://github.com/cheng-zhongliang/bytetrace/blob/master/LICENSE"><img src="https://img.shields.io/github/license/cheng-zhongliang/bytetrace?style=flat-square"></a>
</p>

`bytetrace` is a light-weight dynamic tracer for linux packet drops. It helps you to locate the kernel function and reason for packet drops in a simple and efficient way.

> [!NOTE]
> IPV6 is not supported yet, but it will be added in the future.

## Features

- Locate kernel packet drop reason and function
- Filter by interface, protocol, ip, port, etc.
- Dump packet drop call stack
- Cross-platform support (Linux)
- Easy to use and deploy

## Getting Started

### Installing

To start using `bytetrace`, just run the following command:

```sh
$ git clone https://github.com/cheng-zhongliang/bytetrace.git
$ cd bytetrace
$ make
```

### Usage

```
$ bytetrace -h
Light-weight Dynamic Tracer for Linux Packet Drop

Usage:
  bytetrace [flags] <args>

Flags:
  -p, --proto string       l3/l4 protocol
  -s, --saddr ip           source address
  -d, --daddr ip           destination address
  -S, --sport uint16       source port
  -D, --dport uint16       destination port
  -V, --vlan uint16        VLAN ID
  -i, --interface string   interface name
  -r, --valid-reason       valid drop reason
  -b, --btf string         BTF file path
  -k, --stack              stack trace
  -v, --verbose            verbose output
  -c, --color              output with color
  -h, --help               help for bytetrace
      --version            version for bytetrace
```

### Example

Trace icmp packet drops on interface `ens1f0np0`:

```sh
$ bytetrace -i ens1f0np0 -p 1 -v
```

Output:

```
+-----------+-------------+--------------+----------+-------+-------+--------------+----------------+
| INTERFACE |   SOURCE    | DESTINATION  | PROTOCOL | SPORT | DPORT |   LOCATION   |     REASON     |
+-----------+-------------+--------------+----------+-------+-------+--------------+----------------+
| ens1f0np0 | 192.168.2.1 | 192.168.10.1 |        1 |     0 |     0 | nft_do_chain | NETFILTER_DROP |
+-----------+-------------+--------------+----------+-------+-------+--------------+----------------+
```