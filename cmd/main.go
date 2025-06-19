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
	Version: "0.1.0",
}

func init() {
	cmd.Flags().SortFlags = false
	cmd.Flags().StringVarP(&opt.Proto, "proto", "p", "", "l3/l4 protocol")
	cmd.Flags().IPVarP(&opt.Saddr, "saddr", "s", nil, "source address")
	cmd.Flags().IPVarP(&opt.Daddr, "daddr", "d", nil, "destination address")
	cmd.Flags().Uint16VarP(&opt.Sport, "sport", "S", 0, "source port")
	cmd.Flags().Uint16VarP(&opt.Dport, "dport", "D", 0, "destination port")
	cmd.Flags().Uint16VarP(&opt.VlanId, "vlan", "V", 0, "VLAN ID")
	cmd.Flags().StringVarP(&opt.Interface, "interface", "i", "", "interface name")
	cmd.Flags().BoolVarP(&opt.ValidReason, "valid-reason", "r", false, "valid drop reason")
	cmd.Flags().StringVarP(&opt.BTFPath, "btf", "b", "", "BTF file path")
	cmd.Flags().BoolVarP(&opt.Stack, "stack", "k", false, "stack trace")
	cmd.Flags().BoolVarP(&opt.Verbose, "verbose", "v", false, "verbose output")
	cmd.Flags().BoolVarP(&opt.Color, "color", "c", false, "output with color")
}

func Do(opt bytetrace.Option) (err error) {
	b, err := bytetrace.New(opt)
	if err != nil {
		return err
	}
	defer b.Close()

	if err := b.Attach(); err != nil {
		return err
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() error {
		<-stopper
		return b.Detach()
	}()

	return b.Poll()
}

func main() {
	cmd.Execute()
}
