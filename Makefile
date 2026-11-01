CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
.PHONY: all test
all: build/annakav-cli
build/annakav-cli: linux/cli.c headerUndUtil/sha.c headerUndUtil/sha.h
	mkdir -p build
	$(CC) $(CFLAGS) -std=gnu11 linux/cli.c headerUndUtil/sha.c -o $@
test: all
	python3 tests/cli_test.py build/annakav-cli
