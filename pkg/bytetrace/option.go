package bytetrace

import (
	"bytetrace/pkg/utils"
	"net"
)

type Option struct {
	Proto       string
	Saddr       net.IP
	Daddr       net.IP
	Sport       uint16
	Dport       uint16
	VlanId      uint16
	Stack       bool
	Verbose     bool
	ValidReason bool
	BTFPath     string
	Color       bool
	Interface   string
}

func (o *Option) toTracepointOption() *tracepointOption {
	l3ProtoNum := utils.L3Proto2Num(o.Proto)
	l4ProtoNum := utils.L4Proto2Num(o.Proto)
	return &tracepointOption{
		L3Proto:     l3ProtoNum,
		L4Proto:     l4ProtoNum,
		Saddr:       utils.IpToInt(o.Saddr),
		Daddr:       utils.IpToInt(o.Daddr),
		Sport:       utils.Htons(o.Sport),
		Dport:       utils.Htons(o.Dport),
		VlanId:      o.VlanId,
		Stack:       o.Stack,
		Verbose:     o.Verbose,
		ValidReason: o.ValidReason,
		DevName: func(s string) [16]uint8 {
			var arr [16]uint8
			copy(arr[:], s)
			return arr
		}(o.Interface),
	}
}
