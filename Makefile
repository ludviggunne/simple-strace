CC=gcc
CFLAGS?=
CFLAGS+=-Wall -Wextra -Wpedantic
LDFLAGS=

SRC=$(wildcard *.c)
OBJ=$(SRC:%.c=%.o)
OUT=simple-strace

PREFIX?=.

TBLURL=https://github.com/mebeim/linux-syscalls/raw/refs/heads/master/db/x86/64/x64/v$(shell uname -r | cut -d'.' -f1-2)/table.json

all: $(OUT)

$(OUT): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c print_syscall.h
	$(CC) $(CFLAGS) -o $@ -c $<

print_syscall.h: gen_print_syscall.py
	@chmod +x $<
	@./$< $(TBLURL) $@

install:
	install -Dm755 $(OUT) $(PREFIX)/bin/$(OUT)

clean:
	rm -rf $(OBJ) $(OUT)

.PHONY: clean all
