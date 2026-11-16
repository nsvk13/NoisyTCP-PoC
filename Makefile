# NoisyTCP PoC -- CVE-2026-99288
# Build: make            (needs gcc + glibc headers + pthread)
# On NixOS without a system compiler:  ./build.sh
CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -pthread
LDFLAGS ?= -pthread

BIN = noisytcp
SRC = src/noisytcp.c

.PHONY: all clean selftest

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

selftest: $(BIN)
	./$(BIN) --selftest

clean:
	rm -f $(BIN)
