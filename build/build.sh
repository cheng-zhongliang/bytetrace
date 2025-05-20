#!/bin/bash

set -ex

home=$1

arch=$2

go mod tidy

cd $home/pkg/bytetrace/

bpftool btf dump file /sys/kernel/btf/vmlinux format c > C/vmlinux.h

go get github.com/cilium/ebpf/cmd/bpf2go

go run github.com/cilium/ebpf/cmd/bpf2go -target $arch -tags linux -go-package bytetrace tracepoint C/tracepoint.c

cd $home/cmd/

CGO_ENABLED=0 GOARCH=$arch go build -o $home/build/bytetrace

echo "Build OK"
