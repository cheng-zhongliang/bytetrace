package bytetrace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/olekukonko/tablewriter"
)

type Bytetrace struct {
	coll    *ebpf.Collection
	maps    tracepointMaps
	links   []link.Link
	ring    *ringbuf.Reader
	option  tracepointOption
	samples *samples
	table   *tablewriter.Table
}

func New(opt Option) (*Bytetrace, error) {
	b := new(Bytetrace)

	cs, err := loadTracepoint()
	if err != nil {
		return nil, err
	}

	b.coll, err = ebpf.NewCollection(cs)
	if err != nil {
		return nil, err
	}

	err = b.coll.Assign(&b.maps)
	if err != nil {
		return nil, err
	}

	b.option = opt.toTracepointOption()
	b.samples = newSamples()
	b.links = make([]link.Link, 0, len(b.coll.Programs))
	b.table = tablewriter.NewWriter(os.Stdout)

	return b, nil
}

func (b *Bytetrace) Attach() error {
	err := b.maps.Options.Put(uint32(0), &b.option)
	if err != nil {
		return err
	}

	b.ring, err = ringbuf.NewReader(b.maps.Events)
	if err != nil {
		return err
	}

	for sym, prog := range b.coll.Programs {
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
		b.links = append(b.links, l)
	}

	return nil
}

func (b *Bytetrace) Detach() error {
	if err := b.ring.Close(); err != nil {
		return err
	}

	for _, l := range b.links {
		if err := l.Close(); err != nil {
			return err
		}
	}

	if err := b.maps.Close(); err != nil {
		return err
	}

	b.coll.Close()

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
	key := ev.SkbPtr

	b.samples.add(key, newSample(&ev))

	if isFinshed := ev.Finish != 0; isFinshed {
		b.samples.outputAndRemove(key)
	}
}
