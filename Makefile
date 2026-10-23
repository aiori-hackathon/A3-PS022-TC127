CLANG ?= clang

BPF_SRC := src/xdp/xdp_main.c
BPF_OBJ := build/xdp_main.bpf.o

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@mkdir -p $(@D)
	$(CLANG) -O2 -g -DDEBUG -target bpf -mcpu=v3 -c $< -o $@

clean: 
	rm -rf build