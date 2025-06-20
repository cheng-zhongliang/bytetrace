package utils

import (
	"encoding/binary"
	"fmt"
	"net"
)

var L3Protos = map[uint16]string{
	0x0800: "ipv4",
	0x86dd: "ipv6",
	0x0806: "arp",
	0x888e: "eapol",
}

var L4Protos = map[uint8]string{
	6:  "tcp",
	17: "udp",
	1:  "icmp",
	2:  "igmp",
}

func L3Proto2Num(proto string) uint16 {
	for num, name := range L3Protos {
		if name == proto {
			return num
		}
	}
	return 0
}

func Num2L3Proto(proto uint16) string {
	if name, ok := L3Protos[proto]; ok {
		return name
	}
	return fmt.Sprintf("%d", proto)
}

func L4Proto2Num(proto string) uint8 {
	for num, name := range L4Protos {
		if name == proto {
			return num
		}
	}
	return 0
}

func Num2L4Proto(proto uint8) string {
	if name, ok := L4Protos[proto]; ok {
		return name
	}
	return fmt.Sprintf("%d", proto)
}

func IntToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

func IpToInt(ip net.IP) uint32 {
	if ip = ip.To4(); ip == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}

func Htons(port uint16) uint16 {
	return binary.LittleEndian.Uint16([]byte{byte(port >> 8), byte(port & 0xff)})
}
