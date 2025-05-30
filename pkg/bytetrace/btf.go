package bytetrace

import (
	"os"

	"github.com/cilium/ebpf/btf"
)

func LoadBTF(path string) (*btf.Spec, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	spec, err := btf.LoadSpecFromReader(fh)
	if err != nil {
		return nil, err
	}

	return spec, nil
}
