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
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/olekukonko/tablewriter"
)

type Bytetrace struct {
	objs   tracepointObjects
	link   link.Link
	ring   *ringbuf.Reader
	opt    Option
	table  *tablewriter.Table
	dr     dropResolver
	sf     symbolFinder
	sb     *strings.Builder
	stacks []uint64
}

type dropResolver interface {
	Lookup(reason uint16) string
}

type symbolFinder interface {
	Lookup(pc uint64) string
}

func New(opt Option) (*Bytetrace, error) {
	b := &Bytetrace{}
	opts := &ebpf.CollectionOptions{}

	if opt.BTFPath != "" {
		btfSpec, err := LoadBTF(opt.BTFPath)
		if err != nil {
			return nil, err
		}
		opts.Programs.KernelTypes = btfSpec
	}

	dr, err := dropreason.New()
	if err != nil {
		return nil, err
	}

	sf, err := kallsyms.New()
	if err != nil {
		return nil, err
	}

	err = loadTracepointObjects(&b.objs, opts)
	if err != nil {
		return nil, err
	}

	b.dr = dr
	b.sf = sf
	b.opt = opt
	b.table = tablewriter.NewWriter(os.Stdout)
	b.sb = &strings.Builder{}
	b.stacks = make([]uint64, 64)

	return b, nil
}

func (b *Bytetrace) Attach() error {
	err := b.objs.tracepointMaps.Options.Put(uint32(0), b.opt.toTracepointOption())
	if err != nil {
		return err
	}

	b.ring, err = ringbuf.NewReader(b.objs.tracepointMaps.Events)
	if err != nil {
		return err
	}

	b.link, err = link.Tracepoint("skb", "kfree_skb", b.objs.tracepointPrograms.TraceSkb, nil)
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

	hs := make([]string, 0)
	if b.opt.Verbose {
		hs = append(hs, "Interface")
	}
	hs = append(hs, "Source")
	hs = append(hs, "Destination")
	hs = append(hs, "Protocol")
	hs = append(hs, "SPort")
	hs = append(hs, "DPort")
	hs = append(hs, "Location")
	hs = append(hs, "Reason")
	b.table.SetHeader(hs)

	if b.opt.Color {
		cs := make([]tablewriter.Colors, 0)
		if b.opt.Verbose {
			cs = append(cs, tablewriter.Colors{tablewriter.BgCyanColor})
		}
		cs = append(cs, tablewriter.Colors{tablewriter.BgBlueColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgBlueColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgGreenColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgYellowColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgYellowColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgMagentaColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgRedColor})
		b.table.SetHeaderColor(cs...)
	}

	rows := make([]string, 0)
	if b.opt.Verbose {
		rows = append(rows, string(ev.DevName[:]))
	}
	rows = append(rows, IntToIP(ev.Saddr).String())
	rows = append(rows, IntToIP(ev.Daddr).String())
	rows = append(rows, fmt.Sprintf("%d", ev.Proto))
	rows = append(rows, fmt.Sprintf("%d", ev.Sport))
	rows = append(rows, fmt.Sprintf("%d", ev.Dport))
	rows = append(rows, b.sf.Lookup(ev.Location))
	rows = append(rows, b.dr.Lookup(ev.Reason))
	b.table.Append(rows)

	b.table.Render()

	if b.opt.Stack {
		b.outputCallStack(ev.StackId)
	}
}

func (b *Bytetrace) outputCallStack(StackId uint32) {
	err := b.objs.tracepointMaps.Stacks.Lookup(StackId, b.stacks)
	if err != nil {
		return
	}

	b.sb.Reset()
	for _, pc := range b.stacks {
		if pc == 0 {
			continue
		}
		symbol := b.sf.Lookup(pc)
		if symbol == "" {
			break
		}
		fmt.Fprintf(b.sb, " -> %s\n", symbol)
	}
	fmt.Print(b.sb.String())
}

func (b *Bytetrace) Detach() error {
	if err := b.ring.Close(); err != nil {
		return err
	}

	return b.objs.Close()
}
