package kallsyms

import (
	"bufio"
	"io"
	"unicode"
	"unicode/utf8"
)

type reader struct {
	s    *bufio.Scanner
	line []byte
	word []byte

	err error
}

func newReader(r io.Reader) *reader {
	return &reader{
		s: bufio.NewScanner(r),
	}
}

func (r *reader) Bytes() []byte {
	return r.word
}

func (r *reader) Text() string {
	return string(r.Bytes())
}

func (r *reader) Line() bool {
	for r.s.Scan() {
		line := r.s.Bytes()
		if len(line) == 0 {
			continue
		}

		r.line = line
		r.word = nil

		return true
	}
	if err := r.s.Err(); err != nil {
		r.err = err
	}

	return false
}

func (r *reader) Word() bool {
	if len(r.line) == 0 {
		return false
	}

	start := 0
	for width := 0; start < len(r.line); start += width {
		var c rune
		c, width = utf8.DecodeRune(r.line[start:])
		if !unicode.IsSpace(c) {
			break
		}
	}

	if start == len(r.line) {
		return false
	}

	for width, i := 0, start; i < len(r.line); i += width {
		var c rune
		c, width = utf8.DecodeRune(r.line[i:])
		if unicode.IsSpace(c) {
			r.word = r.line[start:i]
			r.line = r.line[i:]
			return true
		}
	}

	if len(r.line) > start {
		r.word = r.line[start:]
		r.line = nil
		return true
	}

	return false
}

func (r *reader) Err() error {
	return r.err
}
