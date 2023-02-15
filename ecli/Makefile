LIBEUNOMIA := ../../bpf-loader/build/lib/Release/libeunomia.a
LIBWASM_BPF := ../../wasm-runtime/build/libwasm-bpf_LIB.a

.PHONY: build
build: $(LIBEUNOMIA) $(LIBWASM_BPF)
	cargo build

$(LIBEUNOMIA):
	$(MAKE) -C ../../bpf-loader install

$(LIBWASM_BPF):
	mkdir -p ../../wasm-runtime/include/wasm-bpf
	$(MAKE) -C ../../wasm-runtime install

install-deps:
	sudo apt install libssl-dev
	sudo apt install pkg-config
