CC = musl-gcc
CFLAGS = -Wall -Wextra -Wno-unused-function -O0 -static -ggdb -masm=intel -no-pie

SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
LIBS = -lpthread

build: exploit

exploit: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f exploit $(OBJECTS)

.DEFAULT_GOAL := build
