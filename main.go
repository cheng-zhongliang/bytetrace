package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	option := tracepointOption{
		Proto: 1, // IP
		// 127.0.0.1
		Saddr: 0x7f000001,
		Daddr: 0x7f000001,
	}

	b, err := NewBytetrace(option)
	if err != nil {
		panic(err)
	}

	if err := b.Attach(); err != nil {
		panic(err)
	}
	defer b.Detach()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		if err := b.Detach(); err != nil {
			panic(err)
		}
	}()

	if err := b.Poll(); err != nil {
		panic(err)
	}
}
