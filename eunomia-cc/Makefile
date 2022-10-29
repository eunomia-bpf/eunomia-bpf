# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# from https://github.com/libbpf/libbpf-bootstrap/
OUTPUT ?= .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL_SRC := $(abspath ../third_party/bpftool)
BPFTOOL := $(BPFTOOL_SRC)/src/bpftool
LIBBPF_SRC := $(abspath ../third_party/libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
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

.PHONY: all
all: create_eunomia-home

wasi-sdk-16.0-linux.tar.gz:
	wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-16/wasi-sdk-16.0-linux.tar.gz

# clean all data
.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) *.o

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

$(BPFTOOL):
	$(MAKE) -C $(BPFTOOL_SRC)/src

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Get Preprocessor ebpf code
$(OUTPUT)/prep_ebpf.c: client.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,PREPROCESSOR_EBPF,$@)
	$(Q)$(CLANG) -E -P -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) client.bpf.c > $(OUTPUT)/prep_ebpf.c

# generate BTF dump of export data
$(OUTPUT)/export_btf.json: $(OUTPUT)/client.bpf.o | $(OUTPUT)
	$(call msg,GEN-BTF-EXPORT,$@)
	$(Q)$(BPFTOOL) btf dump file $< format c -j > $@

# generate BTF dump of export data
$(OUTPUT)/skel.json: $(OUTPUT)/client.bpf.o | $(OUTPUT)
	$(call msg,GEN-BTF-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< -j > $@

create_eunomia-home: $(LIBBPF_OBJ) $(BPFTOOL)
	rm -rf workspace && mkdir -p workspace/bin workspace/include
	cd cmd && cargo build --release
	cp cmd/target/release/ecc workspace/bin/ecc
	cp $(BPFTOOL) workspace/bin/bpftool
	cp -r .output/bpf workspace/include/bpf
	cp -r ../third_party/vmlinux workspace/include/vmlinux
	rm -rf ~/.eunomia && cp -r workspace ~/.eunomia

EWASM_DIR ?= eunomia-bpf/ewasm
EWASM_BUILD_DIR ?= $(EWASM_DIR)/build

.PHONY: build-wasm
build-wasm: build
	$(call msg,BUILD-WASM)
	$(Q)SOURCE_DIR=$(SOURCE_DIR) make -C eunomia-bpf/ewasm/scripts build

.PHONY: generate_wasm_skel
gen-wasm-skel: build
	$(call msg,GEN-WASM-SKEL)
	$(Q)SOURCE_DIR=$(SOURCE_DIR) make -C eunomia-bpf/ewasm/scripts generate

.PHONY: build
build:
	$(Q)workspace/bin/ecc $(shell ls $(SOURCE_DIR)*.bpf.c) $(shell ls $(SOURCE_DIR)*.bpf.h) -p

.PHONY: docker
docker: wasi-sdk-16.0-linux.tar.gz
	docker build -t yunwei37/ebpm:latest .

.PHONY: docker-push
docker-push:
	docker push yunwei37/ebpm:latest

.PHONY: install_deps
install_deps:
	sudo apt-get update
	sudo apt-get -y install clang libelf1 libelf-dev zlib1g-dev cmake clang llvm

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
