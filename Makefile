.DEFAULT_GOAL := all
CLANG ?= clang
GO ?= go
# Debian/Ubuntu keep asm headers in a multiarch directory; Arch uses /usr/include.
MULTIARCH := $(shell $(CC) -dumpmachine)
BPF_CFLAGS ?= -O2 -g -target bpf -mcpu=v3
BPF_INCLUDES := -I/usr/include/$(MULTIARCH)
include Makefile.core-test

BPF_SRC := src/xdp/xdp_main.c
BPF_OBJ ?= build/xdp_main.bpf.o

.PHONY: all bpf clean controller test test-go test-unit test-harness check-deps monitoring-up monitoring-down

all: $(BPF_OBJ)
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) src/xdp/gcra.h src/xdp/global_bucket.h Makefile
	@mkdir -p $(@D)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

CONTROLLER_DIR := src/controller
CONTROLLER_OBJ := $(CONTROLLER_DIR)/bpf/xdp_main.bpf.o

$(CONTROLLER_OBJ): $(BPF_OBJ)
	@mkdir -p $(@D)
	cp $< $@

controller: all $(CONTROLLER_OBJ)
	cd $(CONTROLLER_DIR) && $(GO) build -o ../../build/byteguard .

test: test-unit test-harness test-go
test-unit: build/gcra_test build/gcra_concurrency_test
	./build/gcra_test
	./build/gcra_concurrency_test
build/gcra_test: src/tests/gcra_test.c src/xdp/gcra.h
	@mkdir -p build
	$(CC) -O2 -Wall -Wextra -Wno-unknown-pragmas -o $@ $<
build/gcra_concurrency_test: src/tests/gcra_concurrency_test.c src/xdp/gcra.h
	@mkdir -p build
	$(CC) -O2 -Wall -Wextra -Wno-unknown-pragmas -pthread -o $@ $<
test-go: $(CONTROLLER_OBJ)
	cd $(CONTROLLER_DIR) && $(GO) test -race ./...
test-harness:
	python3 -m unittest discover -s scripts/bench -p 'test_*.py' -v
	python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
check-deps:
	bash scripts/check-deps.sh
monitoring-up:
	docker compose up -d
monitoring-down:
	docker compose down
clean:
	# Preserve benchmark measurements and existing tracked controller binaries.
	rm -f build/xdp_main.bpf.o build/byteguard build/gcra_test build/gcra_concurrency_test build/xdp_core_test.bpf.o build/byteguard-core-test $(CONTROLLER_OBJ)
