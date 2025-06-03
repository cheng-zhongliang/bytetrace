package dropreason

import (
	"os"
	"regexp"
	"strconv"
)

type DropReason struct {
	reasons [256]string
}

func New() (*DropReason, error) {
	dr := &DropReason{}

	content, err := os.ReadFile("/sys/kernel/debug/tracing/events/skb/kfree_skb/format")
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`\{\s*(\d+),\s*"([^"]+)"\s*\}`)

	matches := re.FindAllStringSubmatch(string(content), -1)

	for _, match := range matches {
		if len(match) == 3 {
			index, err := strconv.Atoi(match[1])
			if err != nil {
				return nil, err
			}
			reason := match[2]
			dr.reasons[index] = reason
		}
	}

	return dr, nil
}

func (dr *DropReason) Lookup(reason uint16) string {
	return dr.reasons[reason]
}
