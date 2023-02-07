LIBEUNOMIA := ../../bpf-loader/build/lib/Release/libeunomia.a
LIBWASM_BPF := ../../wasm-runtime/build/libwasm-bpf_LIB.a

.PHONY: build
build: $(LIBEUNOMIA) $(LIBWASM_BPF)
	cargo build --release

$(LIBEUNOMIA):
	$(MAKE) -C ../../bpf-loader install

$(LIBWASM_BPF):
	$(MAKE) -C ../../wasm-runtime install

install-deps:
	sudo apt install libssl-dev
	sudo apt install pkg-config
