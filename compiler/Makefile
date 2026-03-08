# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# from https://github.com/libbpf/libbpf-bootstrap/
OUTPUT ?= .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL_SRC := $(abspath ../third_party/bpftool)
BPFTOOL := $(BPFTOOL_SRC)/src/bpftool
ECC := cmd/target/release/ecc-rs
LIBEUNOMIA_TARGET_DIR := ../bpf-loader-rs/target/eunomia-standalone-runtime
LIBEUNOMIA := $(LIBEUNOMIA_TARGET_DIR)/release/libeunomia.a
LIBEUNOMIA_LINKFLAGS := $(LIBEUNOMIA_TARGET_DIR)/release/libeunomia.a.linkflags
WORKSPACE_ECC := workspace/bin/ecc-rs
WORKSPACE_LIBEUNOMIA := workspace/libeunomia.a
WORKSPACE_LIBEUNOMIA_LINKFLAGS := workspace/libeunomia.a.linkflags
STANDALONE_RUNTIME_SOURCES := $(shell find ../bpf-loader-rs/bpf-loader-c-wrapper/src ../bpf-loader-rs/bpf-loader-lib/src -type f -name '*.rs') ../bpf-loader-rs/bpf-loader-c-wrapper/Cargo.toml ../bpf-loader-rs/bpf-loader-lib/Cargo.toml ../bpf-loader-rs/Cargo.toml ../bpf-loader-rs/Cargo.lock
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/' | sed 's/riscv64/riscv/')
VMLINUX := ../third_party/vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
SOURCE_DIR ?= /src/
SOURCE_FILE_INCLUDES ?= 
INCLUDES := -I$(SOURCE_DIR) $(SOURCE_FILE_INCLUDES) -I$(OUTPUT) -I$(LIBBPF_SRC)/../include/uapi -I$(dir $(VMLINUX))
PYTHON_SCRIPTS := $(abspath libs/scripts)
CFLAGS := -g -Wall -Wno-unused-function #-fsanitize=address

PACKAGE_NAME := client

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

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all install
all: $(WORKSPACE_ECC) $(WORKSPACE_LIBEUNOMIA) $(WORKSPACE_LIBEUNOMIA_LINKFLAGS)

wasi-sdk-16.0-linux.tar.gz:
	wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-16/wasi-sdk-16.0-linux.tar.gz

# clean all data
.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) *.o workspace
	cd cmd && cargo clean

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(BPFTOOL):
	$(MAKE) -C $(BPFTOOL_SRC)/src

$(WORKSPACE_LIBEUNOMIA) $(WORKSPACE_LIBEUNOMIA_LINKFLAGS): $(STANDALONE_RUNTIME_SOURCES)
	mkdir -p $(LIBEUNOMIA_TARGET_DIR)/release
	( cargo rustc --manifest-path ../bpf-loader-rs/Cargo.toml -p bpf-loader-c-wrapper --target-dir $(LIBEUNOMIA_TARGET_DIR) --release -- --print=native-static-libs 2>&1 | awk -F 'native-static-libs: ' '/native-static-libs:/ { print $$2 }'; pkg-config --static --libs libelf zlib 2>/dev/null || true ) | awk '{ for (i = 1; i <= NF; i++) { if ($$i != "-lgcc_s") { printf "%s ", $$i } } } END { print "" }' > $(LIBEUNOMIA_LINKFLAGS)
	test -s $(LIBEUNOMIA_LINKFLAGS)
	test -f $(LIBEUNOMIA)
	mkdir -p workspace
	cp $(LIBEUNOMIA) $(WORKSPACE_LIBEUNOMIA)
	cp $(LIBEUNOMIA_LINKFLAGS) $(WORKSPACE_LIBEUNOMIA_LINKFLAGS)

$(ECC): $(BPFTOOL)
	cd cmd && cargo build --release
	cargo install cargo-out-dir
	cd cmd && cargo build # Run a debug build to create the workspace directory 
	# cd cmd && cp -r `cargo-out-dir`/workspace ..

$(WORKSPACE_ECC): $(ECC)
	mkdir -p workspace/bin
	cp $(ECC) $(WORKSPACE_ECC)

XDG_DATA_HOME ?= ${HOME}/.local/share
EUNOMIA_HOME ?= $(XDG_DATA_HOME)/eunomia

install: all
	mkdir -p $(EUNOMIA_HOME) && cp -r workspace/. $(EUNOMIA_HOME)/
.PHONY: test
test:
	cargo install clippy-sarif sarif-fmt grcov
	rustup component add llvm-tools-preview
	cp -r cmd/test /tmp
	cd cmd && CARGO_INCREMENTAL=0 RUSTFLAGS="-Cinstrument-coverage -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off" RUSTDOCFLAGS="-Cpanic=abort" cargo test
	cd cmd && grcov . --binary-path ./target/debug/ --llvm -s . -t html --branch --ignore-not-existing -o ./coverage/
	cd cmd && grcov . --binary-path ./target/debug/ --llvm -s . -t lcov --branch --ignore-not-existing -o ./lcov.info
	cd cmd && cargo clippy --all-features --message-format=json | clippy-sarif | tee rust-clippy-results.sarif | sarif-fmt
	cd cmd && cargo fmt --check

# TODO Waiting to discuss how to handle scripts
#
# .PHONY: build-wasm
# build-wasm: build
# 	$(call msg,BUILD-WASM)
# 	$(Q)SOURCE_DIR=$(SOURCE_DIR) make -C workspace/scripts build
#
# .PHONY: generate_wasm_skel
# gen-wasm-skel: build
# 	$(call msg,GEN-WASM-SKEL)
# 	$(Q)SOURCE_DIR=$(SOURCE_DIR) make -C workspace/scripts generate

.PHONY: build
build-ebpf-program:
	$(Q)$(EUNOMIA_HOME)/bin/ecc-rs $(shell ls $(SOURCE_DIR)*.bpf.c) $(shell ls -h1 $(SOURCE_DIR)*.h | grep -v .*\.bpf\.h)

.PHONY: docker
docker: wasi-sdk-16.0-linux.tar.gz
	$(MAKE)
	sudo docker build -t ghcr.io/eunomia-bpf/ecc-$(shell uname -m):latest .
ifeq ("$(shell uname -m)", "x86_64")
	docker build -t ghcr.io/eunomia-bpf/ecc-`uname -m`:latest .
endif

.PHONY: docker-push
docker-push:
	sudo docker push ghcr.io/eunomia-bpf/ecc-$(shell uname -m):latest
ifeq ("$(shell uname -m)", "x86_64")
	docker push ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
endif

.PHONY: install-deps
install-deps:
	sudo apt-get update
	sudo apt-get -y install clang libelf1 libelf-dev zlib1g-dev libzstd-dev liblzma-dev cmake llvm libclang-dev

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
