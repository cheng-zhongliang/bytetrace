package bytetrace

import (
	"bytes"
	"bytetrace/pkg/dropreason"
	"bytetrace/pkg/kallsyms"
	. "bytetrace/pkg/utils"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/olekukonko/tablewriter"
)

type Bytetrace struct {
	objs   tracepointObjects
	link   link.Link
	ring   *ringbuf.Reader
	option tracepointOption
	table  *tablewriter.Table
}

func New(opt Option) (*Bytetrace, error) {
	b := new(Bytetrace)

	err := loadTracepointObjects(&b.objs, nil)
	if err != nil {
		return nil, err
	}

	b.option = opt.toTracepointOption()
	b.table = tablewriter.NewWriter(os.Stdout)

	return b, nil
}

func (b *Bytetrace) Attach() error {
	err := b.objs.tracepointMaps.Options.Put(uint32(0), &b.option)
	if err != nil {
		return err
	}

	b.ring, err = ringbuf.NewReader(b.objs.tracepointMaps.Events)
	if err != nil {
		return err
	}

	b.link, err = link.AttachTracing(link.TracingOptions{
		Program: b.objs.tracepointPrograms.KfreeSkb,
	})
	if err != nil {
		return err
	}

	return nil
}

func (b *Bytetrace) Poll() error {
	var event tracepointEvent
	for {
		record, err := b.ring.Read()
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

		b.onEvent(event)
	}
}

func (b *Bytetrace) onEvent(ev tracepointEvent) {
	b.table.ClearRows()
	b.table.SetHeader([]string{
		"Reason",
		"Location",
		"Source",
		"Destination",
		"Protocol",
		"SPort",
		"DPort",
	})
	b.table.Append([]string{
		dropreason.Lookup(ev.Reason),
		kallsyms.Lookup(ev.Location),
		IntToIP(ev.Saddr).String(),
		IntToIP(ev.Daddr).String(),
		fmt.Sprintf("%d", ev.Proto),
		fmt.Sprintf("%d", ev.Sport),
		fmt.Sprintf("%d", ev.Dport),
	})
	b.table.Render()
}

func (b *Bytetrace) Detach() error {
	if err := b.ring.Close(); err != nil {
		return err
	}

	return b.objs.Close()
}
