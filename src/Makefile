.PHONY: all clean

CC = gcc
CFLAGS = -Wall -D__USER_SPACE__
LDFLAGS =
LDLIBS = -lbpf

SRC = bytetrace.c argparse.c trace.c log.c proto.c output.c 
TARGET = bytetrace

all: $(TARGET)

$(TARGET): $(SRC)
	$(MAKE) -C progs/
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	$(MAKE) -C progs/ clean
	rm -f $(TARGET) *.o
