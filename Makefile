.DEFAULT_GOAL:=all
include Makefile.core-test
CLANG ?= clang

BPF_SRC := src/xdp/xdp_main.c
BPF_OBJ := build/xdp_main.bpf.o

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@mkdir -p $(@D)
	$(CLANG) -O2 -g -DDEBUG -target bpf -mcpu=v3 \
	-I/usr/include/x86_64-linux-gnu \
	-c $< -o $@

CONTROLLER_DIR := src/controller
CONTROLLER_OBJ := $(CONTROLLER_DIR)/bpf/xdp_main.bpf.o

.PHONY: controller

$(CONTROLLER_OBJ): $(BPF_OBJ)
	@mkdir -p $(@D)
	cp $< $@

controller: all $(CONTROLLER_OBJ)
	cd $(CONTROLLER_DIR) && go build -o byteguard .

clean: 
	rm -rf build