package bytetrace

import (
	"fmt"
	"os"
	"strings"

	"bytetrace/pkg/dropreason"
	"bytetrace/pkg/kallsyms"
	"bytetrace/pkg/utils"

	"github.com/olekukonko/tablewriter"
)

type dropResolver interface {
	Lookup(reason uint16) string
}

type symbolFinder interface {
	Lookup(pc uint64) string
}

type table struct {
	writer  *tablewriter.Table
	dr      dropResolver
	sf      symbolFinder
	sb      *strings.Builder
	verbose bool
	color   bool
}

func newTable(verbose, color bool) (*table, error) {
	t := &table{verbose: verbose, color: color}

	dr, err := dropreason.New()
	if err != nil {
		return nil, err
	}

	sf, err := kallsyms.New()
	if err != nil {
		return nil, err
	}

	t.dr = dr
	t.sf = sf
	t.sb = &strings.Builder{}
	t.writer = tablewriter.NewWriter(os.Stdout)

	t.setup()

	return t, nil
}

func (t *table) output(ev *tracepointEvent, stacks []uint64) {
	t.writer.ClearRows()
	rows := make([]string, 0)
	if t.verbose {
		rows = append(rows, string(ev.DevName[:]))
		rows = append(rows, fmt.Sprintf("%d", ev.VlanId))
	}
	rows = append(rows, utils.IntToIP(ev.Saddr).String())
	rows = append(rows, utils.IntToIP(ev.Daddr).String())
	rows = append(rows, fmt.Sprintf("%d", ev.Proto))
	rows = append(rows, fmt.Sprintf("%d", ev.Sport))
	rows = append(rows, fmt.Sprintf("%d", ev.Dport))
	rows = append(rows, t.sf.Lookup(ev.Location))
	rows = append(rows, t.dr.Lookup(ev.Reason))
	t.writer.Append(rows)
	t.writer.Render()

	if stacks != nil {
		t.sb.Reset()
		for _, pc := range stacks {
			if pc == 0 {
				continue
			}
			symbol := t.sf.Lookup(pc)
			if symbol == "" {
				break
			}
			fmt.Fprintf(t.sb, " -> %s\n", symbol)
		}
		fmt.Print(t.sb.String())
	}
}

func (t *table) setup() {
	hs := make([]string, 0)
	if t.verbose {
		hs = append(hs, "Interface")
		hs = append(hs, "Vlan")
	}
	hs = append(hs, "Source")
	hs = append(hs, "Destination")
	hs = append(hs, "Protocol")
	hs = append(hs, "SPort")
	hs = append(hs, "DPort")
	hs = append(hs, "Location")
	hs = append(hs, "Reason")
	t.writer.SetHeader(hs)

	if t.color {
		cs := make([]tablewriter.Colors, 0)
		if t.verbose {
			cs = append(cs, tablewriter.Colors{tablewriter.BgCyanColor})
			cs = append(cs, tablewriter.Colors{tablewriter.BgWhiteColor})
		}
		cs = append(cs, tablewriter.Colors{tablewriter.BgBlueColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgBlueColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgGreenColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgYellowColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgYellowColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgMagentaColor})
		cs = append(cs, tablewriter.Colors{tablewriter.BgRedColor})
		t.writer.SetHeaderColor(cs...)
	}
}
