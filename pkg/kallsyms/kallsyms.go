package kallsyms

import (
	"math"
	"os"
	"strconv"
)

var cache = make(map[uint64]string)

func Lookup(pc uint64) string {
	if symbol, ok := cache[pc]; ok {
		return symbol
	}

	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	symbol := "unknown"
	min_delta := uint64(math.MaxUint64)

	r := newReader(f)
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
		if delta < min_delta {
			min_delta = delta
			r.Word()
			r.Word()
			symbol = r.Text()
		}
	}
	if r.err != nil {
		panic(r.err)
	}

	cache[pc] = symbol

	return symbol
}
