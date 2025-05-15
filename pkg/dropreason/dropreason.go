package dropreason

import (
	"os"
	"regexp"
	"strconv"
)

var reasons [256]string

func init() {
	content, err := os.ReadFile("/sys/kernel/debug/tracing/events/skb/kfree_skb/format")
	if err != nil {
		panic(err)
	}

	re := regexp.MustCompile(`\{\s*(\d+),\s*"([^"]+)"\s*\}`)

	matches := re.FindAllStringSubmatch(string(content), -1)

	for _, match := range matches {
		if len(match) == 3 {
			index, err := strconv.Atoi(match[1])
			if err != nil {
				panic(err)
			}
			reason := match[2]
			reasons[index] = reason
		}
	}
}

func Lookup(code uint16) string {
	return reasons[code]
}
