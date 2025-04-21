package main

import (
	"encoding/binary"
	"net"
)

func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, ipNum)
	return ip
}
