package bytetrace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Bytetrace struct {
	objs   tracepointObjects
	link   link.Link
	ring   *ringbuf.Reader
	option tracepointOption
}

func New(opt Option) (*Bytetrace, error) {
	b := new(Bytetrace)

	err := loadTracepointObjects(&b.objs, nil)
	if err != nil {
		return nil, err
	}

	b.option = opt.toTracepointOption()

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
	key := ev.SkbPtr
	reason := ev.Reason
	fmt.Printf("%v %v\n", key, reason)
}

func (b *Bytetrace) Detach() error {
	if err := b.ring.Close(); err != nil {
		return err
	}

	return b.objs.Close()
}
