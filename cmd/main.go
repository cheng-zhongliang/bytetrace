package main

import (
	"bytetrace/pkg/bytetrace"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var opt bytetrace.Option

var cmd = &cobra.Command{
	Use:                   "bytetrace [flags] <args>",
	Long:                  "Light-weight Dynamic Tracer for Linux Packet Drop",
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return Do(opt)
	},
}

func init() {
	cmd.Flags().SortFlags = false
	cmd.Flags().Uint8VarP(&opt.Proto, "proto", "p", 0, "l3/l4 protocol")
	cmd.Flags().IPVarP(&opt.Saddr, "saddr", "s", nil, "source address")
	cmd.Flags().IPVarP(&opt.Daddr, "daddr", "d", nil, "destination address")
	cmd.Flags().Uint16VarP(&opt.Sport, "sport", "S", 0, "source port")
	cmd.Flags().Uint16VarP(&opt.Dport, "dport", "D", 0, "destination port")
}

func Do(opt bytetrace.Option) (err error) {
	b, err := bytetrace.New(opt)
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
