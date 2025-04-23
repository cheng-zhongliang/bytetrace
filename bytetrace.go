package main

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/olekukonko/tablewriter"
)

type sample struct {
	Ele   *list.Element
	Event *tracepointEvent
}

type Bytetrace struct {
	Coll    *ebpf.Collection
	Maps    tracepointMaps
	Links   []link.Link
	Ring    *ringbuf.Reader
	Option  tracepointOption
	Samples map[uint64]*list.List
	Table   *tablewriter.Table
}

func NewBytetrace(opt tracepointOption) (*Bytetrace, error) {
	b := new(Bytetrace)

	collSpec, err := loadTracepoint()
	if err != nil {
		return nil, err
	}

	b.Coll, err = ebpf.NewCollection(collSpec)
	if err != nil {
		return nil, err
	}

	err = b.Coll.Assign(&b.Maps)
	if err != nil {
		return nil, err
	}

	b.Option = opt
	b.Samples = make(map[uint64]*list.List)
	b.Links = make([]link.Link, 0, len(b.Coll.Programs))
	b.Table = tablewriter.NewWriter(os.Stdout)

	return b, nil
}

func (b *Bytetrace) Attach() error {
	err := b.Maps.Options.Put(uint32(0), &b.Option)
	if err != nil {
		return err
	}

	b.Ring, err = ringbuf.NewReader(b.Maps.Events)
	if err != nil {
		return err
	}

	for sym, prog := range b.Coll.Programs {
		var l link.Link
		var err error
		switch prog.Type() {
		case ebpf.Kprobe:
			l, err = link.Kprobe(sym, prog, nil)
		case ebpf.Tracing:
			l, err = link.AttachTracing(link.TracingOptions{
				Program: prog,
			})
		default:
			return errors.ErrUnsupported
		}
		if err != nil {
			return err
		}
		b.Links = append(b.Links, l)
	}

	return nil
}

func (b *Bytetrace) Detach() error {
	if err := b.Ring.Close(); err != nil {
		return err
	}

	for _, l := range b.Links {
		if err := l.Close(); err != nil {
			return err
		}
	}

	if err := b.Maps.Close(); err != nil {
		return err
	}

	b.Coll.Close()

	return nil
}

func (b *Bytetrace) Poll() error {
	var event tracepointEvent
	for {
		record, err := b.Ring.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}

		buffer := bytes.NewBuffer(record.RawSample)
		err = binary.Read(buffer, binary.LittleEndian, &event)
		if err != nil {
			continue
		}

		b.OnEvent(event)
	}
}

func (b *Bytetrace) OnEvent(ev tracepointEvent) {
	sp := new(sample)
	sp.Event = &ev

	if _, ok := b.Samples[ev.SkbPtr]; !ok {
		b.Samples[ev.SkbPtr] = list.New()
	}
	sp.Ele = b.Samples[ev.SkbPtr].PushBack(sp)

	if isFinshed := ev.Finish != 0; isFinshed {
		if l, ok := b.Samples[ev.SkbPtr]; ok {
			b.Output(l)
		}
		delete(b.Samples, ev.SkbPtr)
	}
}

func (b *Bytetrace) Output(l *list.List) {
	b.Table.ClearRows()
	b.Table.SetHeader([]string{
		"Symbol",
		"Source",
		"Destination",
		"Protocol",
		"SPort",
		"DPort",
	})
	for e := l.Front(); e != nil; e = e.Next() {
		ev := e.Value.(*sample).Event
		b.Table.Append([]string{
			string(ev.Symbol[:]),
			intToIP(ev.Saddr).String(),
			intToIP(ev.Daddr).String(),
			fmt.Sprintf("%d", ev.Proto),
			fmt.Sprintf("%d", ev.Sport),
			fmt.Sprintf("%d", ev.Dport),
		})
	}
	b.Table.Render()
}
