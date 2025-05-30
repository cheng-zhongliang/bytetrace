package kallsyms

import (
	"bytes"
	"math"
	"os"
	"strconv"
)

type Kallsyms struct {
	caches  map[uint64]string
	content []byte
}

func New() (*Kallsyms, error) {
	content, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return nil, err
	}

	return &Kallsyms{
		caches:  make(map[uint64]string),
		content: content,
	}, nil
}

func (k *Kallsyms) Lookup(pc uint64) string {
	if symbol, ok := k.caches[pc]; ok {
		return symbol
	}

	br := bytes.NewReader(k.content)

	symbol := "unknown"
	minDelta := uint64(math.MaxUint64)

	r := newReader(br)
	for r.Line() {
		r.Word()

		sppc, err := strconv.ParseUint(r.Text(), 16, 64)
		if err != nil {
			panic(err)
		}

		if sppc > pc {
			continue
		}

		delta := pc - sppc
		if delta < minDelta {
			minDelta = delta

			r.Word()
			r.Word()

			symbol = r.Text()
		}
	}
	if r.err != nil {
		panic(r.err)
	}

	k.caches[pc] = symbol

	return symbol
}
