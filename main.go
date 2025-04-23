package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var opt tracepointOption

var cmd = &cobra.Command{
	Use:                   "bytetrace [flags] <args>",
	Long:                  "Light-weight Dynamic Tracer for Linux Network Stack",
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		if err := Do(opt); err != nil {
			cmd.PrintErrln(err)
		}
	},
}

func init() {
	cmd.Flags().SortFlags = false
	cmd.Flags().Uint8VarP(&opt.Proto, "proto", "p", 0, "l3/l4 protocol")
	cmd.Flags().Uint32VarP(&opt.Saddr, "saddr", "s", 0, "source address")
	cmd.Flags().Uint32VarP(&opt.Daddr, "daddr", "d", 0, "destination address")
	cmd.Flags().Uint16VarP(&opt.Sport, "sport", "S", 0, "source port")
	cmd.Flags().Uint16VarP(&opt.Dport, "dport", "D", 0, "destination port")
}

func Do(opt tracepointOption) (err error) {
	b, err := NewBytetrace(opt)
	if err != nil {
		return err
	}

	if err := b.Attach(); err != nil {
		return err
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, os.Kill, syscall.SIGTERM)

	go func() error {
		<-stopper
		return b.Detach()
	}()

	return b.Poll()
}

func main() {
	cmd.Execute()
}
