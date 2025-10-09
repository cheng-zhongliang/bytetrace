.PHONY: all clean gen_skel

CC = clang
CFLAGS = -g -O2 -target bpf -D__KERNEL_SPACE__
LDFLAGS = -I../

SRC = tracepoint.c 
TARGET = tracepoint
OUTPUT = ../tracepoint.h

all: $(TARGET) gen_skel

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -c -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) $(OUTPUT)

gen_skel:
	xxd -i -u tracepoint > $(OUTPUT)


