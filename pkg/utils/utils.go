package utils

import (
	"encoding/binary"
	"net"
)

func IntToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, ipNum)
	return ip
}

func IpToInt(ip net.IP) uint32 {
	if ip = ip.To4(); ip == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}
