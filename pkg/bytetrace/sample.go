package bytetrace

import (
	"bytetrace/pkg/utils"
	"container/list"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
)

type sample struct {
	Ele    *list.Element
	Symbol [64]uint8
	Proto  uint8
	Saddr  uint32
	Daddr  uint32
	Sport  uint16
	Dport  uint16
}

func newSample(ev *tracepointEvent) *sample {
	return &sample{
		Symbol: ev.Symbol,
		Proto:  ev.Proto,
		Saddr:  ev.Saddr,
		Daddr:  ev.Daddr,
		Sport:  ev.Sport,
		Dport:  ev.Dport,
	}
}

type samples struct {
	Samples map[uint64]*list.List
	Table   *tablewriter.Table
}

func newSamples() *samples {
	return &samples{
		Samples: make(map[uint64]*list.List),
		Table:   tablewriter.NewWriter(os.Stdout),
	}
}

func (ss *samples) add(key uint64, s *sample) {
	if _, ok := ss.Samples[key]; !ok {
		ss.Samples[key] = list.New()
	}
	s.Ele = ss.Samples[key].PushBack(s)
}

func (ss *samples) outputAndRemove(key uint64) {
	if l, ok := ss.Samples[key]; ok {
		ss.Table.ClearRows()
		ss.Table.SetHeader([]string{
			"Symbol",
			"Source",
			"Destination",
			"Protocol",
			"SPort",
			"DPort",
		})
		for e := l.Front(); e != nil; e = e.Next() {
			s := e.Value.(*sample)
			ss.Table.Append([]string{
				string(s.Symbol[:]),
				utils.IntToIP(s.Saddr).String(),
				utils.IntToIP(s.Daddr).String(),
				fmt.Sprintf("%d", s.Proto),
				fmt.Sprintf("%d", s.Sport),
				fmt.Sprintf("%d", s.Dport),
			})
		}
		ss.Table.Render()
		delete(ss.Samples, key)
	}
}
