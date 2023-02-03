.PHONY: all

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := ../../third_party/vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
CLANG = clang
LLVM_STRIP = llvm-strip


# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all
all: bootstrap.wasm bootstrap.bpf.o

.PHONY: clean
clean:
	rm -rf *.o *.json *.wasm *.skel.h

# Build BPF code
%.bpf.o: %.bpf.c $(wildcard %.h) $(VMLINUX)
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	llvm-strip -g $@ # strip useless DWARF info

# clone wasm-bpftool
bpftool:
	git clone https://github.com/eunomia-bpf/bpftool --recursive

# compile bpftool
bpftool/src/bpftool: bpftool
	cd bpftool && git checkout origin/wasm-bpftool
	cd bpftool/src && make

# generate c skeleton
%.skel.h: %.bpf.o bpftool/src/bpftool
	bpftool/src/bpftool gen skeleton -j $< > $@

# generate wasm bpf header for pass struct event
bootstrap.wasm.h: bootstrap.bpf.o bpftool/src/bpftool
	ecc bootstrap.h --header-only
	bpftool/src/bpftool btf dump file $< format c -j > $@

# compile for wasm with wasi-sdk
WASI_CLANG = /opt/wasi-sdk/bin/clang
WASI_CFLAGS = -O2 --sysroot=/opt/wasi-sdk/share/wasi-sysroot -Wl,--allow-undefined

bootstrap.wasm: bootstrap.c bootstrap.skel.h
	$(WASI_CLANG) $(WASI_CFLAGS) -o $@ $<