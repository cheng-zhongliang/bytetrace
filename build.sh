#!/bin/bash

set -ex

go mod tidy

go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -tags linux -go-package main tracepoint C/tracepoint.c

mv tracepoint_x86_bpfel.go tracepoint.go

sed -i 's|tracepoint_x86_bpfel.o|C/tracepoint.o|' tracepoint.go

mv tracepoint_x86_bpfel.o C/tracepoint.o

go build

echo "Build OK"
