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

func ipToInt(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip.To4())
}
