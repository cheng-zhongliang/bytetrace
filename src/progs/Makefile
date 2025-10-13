.PHONY: all clean gen_skel gen_vmlinux_h

CC = clang
CFLAGS = -g -O2 -target bpf -D__KERNEL_SPACE__
LDFLAGS = -I../

SRC = tracepoint.c 
TARGET = tracepoint
OUTPUT = ../tracepoint.h

all: gen_vmlinux_h $(TARGET) gen_skel

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -c -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) $(OUTPUT) vmlinux.h

gen_skel:
	xxd -i -u tracepoint > $(OUTPUT)

gen_vmlinux_h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


