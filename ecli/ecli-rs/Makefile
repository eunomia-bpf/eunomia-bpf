LIBEUNOMIA := ../../bpf-loader/build/lib/Release/libeunomia.a
LIBEWASM := ../../wasm-runtime/build/lib/Release/libewasm.a

.PHONY: build
build: $(LIBEUNOMIA) $(LIBEWASM)
	cargo build --release

$(LIBEUNOMIA):
	$(MAKE) -C ../../bpf-loader install

$(LIBEWASM):
	$(MAKE) -C ../../wasm-runtime install