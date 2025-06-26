package bytetrace

import (
	"bytes"

	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Bytetrace struct {
	objs     tracepointObjects
	link     link.Link
	ring     *ringbuf.Reader
	traceOpt *tracepointOption
	stacks   []uint64
	console  console
}

type console interface {
	output(ev *tracepointEvent, stacks []uint64)
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

	err := loadTracepointObjects(&b.objs, opts)
	if err != nil {
		return nil, err
	}

	b.console, err = newTable(opt.Verbose, opt.Color)
	if err != nil {
		return nil, err
	}

	b.traceOpt = opt.toTracepointOption()
	b.stacks = make([]uint64, 64)

	return b, nil
}

func (b *Bytetrace) Attach() error {
	err := b.objs.tracepointMaps.Options.Put(uint32(0), b.traceOpt)
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

		b.onEvent(&event)
	}
}

func (b *Bytetrace) onEvent(ev *tracepointEvent) {
	if ev.StackId != 0 {
		err := b.objs.tracepointMaps.Stacks.Lookup(ev.StackId, &b.stacks)
		if err != nil {
			return
		}
		b.console.output(ev, b.stacks)
	} else {
		b.console.output(ev, nil)
	}
}

func (b *Bytetrace) Detach() error {
	if err := b.ring.Close(); err != nil {
		return err
	}

	return b.link.Close()
}

func (b *Bytetrace) Close() error {
	return b.objs.Close()
}
