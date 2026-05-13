CC := cc
CPPFLAGS := -Iinclude/bytetrace
CFLAGS := -O2 -g -std=c11 -Wall -Wextra -Wpedantic

TARGET := bytetrace
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ -o $@

clean:
	$(RM) $(OBJS) $(TARGET)
