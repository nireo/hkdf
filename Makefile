cc ?= cc
cflags ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2 -I.

test_src := tests/test.c
test_bin := tests/test

.PHONY: all test clean

all: $(test_bin)

$(test_bin): $(test_src) hkdf.h
	$(cc) $(cflags) $< -o $@

test: $(test_bin)
	./$(test_bin)

clean:
	rm -f $(test_bin) tests/test_sha256
