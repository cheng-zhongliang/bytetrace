package bytetrace

import (
	"bytetrace/pkg/utils"
	"net"
)

type Option struct {
	Proto       uint8
	Saddr       net.IP
	Daddr       net.IP
	Sport       uint16
	Dport       uint16
	Stack       bool
	Verbose     bool
	ValidReason bool
	BTFPath     string
	Color       bool
	Interface   string
}

func (o *Option) toTracepointOption() *tracepointOption {
	return &tracepointOption{
		Proto:       o.Proto,
		Saddr:       utils.IpToInt(o.Saddr),
		Daddr:       utils.IpToInt(o.Daddr),
		Sport:       o.Sport,
		Dport:       o.Dport,
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
