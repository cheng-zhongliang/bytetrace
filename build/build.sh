#!/bin/bash

set -ex

home=$1

go mod tidy

cd $home/pkg/bytetrace/

go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -tags linux -go-package bytetrace tracepoint C/tracepoint.c

mv tracepoint_x86_bpfel.go tracepoint.go

sed -i 's|tracepoint_x86_bpfel.o|C/tracepoint.o|' tracepoint.go

mv tracepoint_x86_bpfel.o C/tracepoint.o

cd $home/cmd/

go build -o $home/build/bytetrace

echo "Build OK"
