# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# from https://github.com/libbpf/libbpf-bootstrap/
OUTPUT ?= .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL := $(abspath libs/bpftools/src/bpftool)
LIBBPF_SRC := $(abspath libs/libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := libs/vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
SOURCE_DIR ?= /src/
SOURCE_FILE_INCLUDES ?= 
INCLUDES := -I$(SOURCE_DIR) $(SOURCE_FILE_INCLUDES) -I$(OUTPUT) -Ilibs/libbpf/include/uapi -I$(dir $(VMLINUX))
PYTHON_SCRIPTS := $(abspath libs/scripts)
CFLAGS := -g -Wall -Wno-unused-function #-fsanitize=address

PACKAGE_NAME := client
APPS = client

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
all: $(APPS)

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
	$(MAKE) -C libs/bpftools/src

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/cJSON.o: libs/cJSON.c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/create_skel_json.o: libs/create_skel_json.c $(OUTPUT)/secgen
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/secgen: libs/gen.c
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -Ilibs/libbpf/src -Ilibs/libbpf/include $(filter %.c,$^) $(LIBBPF_OBJ) -lelf -lz -o $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(OUTPUT)/cJSON.o $(OUTPUT)/create_skel_json.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

# Get Preprocessor ebpf code
$(OUTPUT)/prep_ebpf.c: client.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,PREPROCESSOR_EBPF,$@)
	$(Q)$(CLANG) -E -P -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) client.bpf.c > $(OUTPUT)/prep_ebpf.c

# generate AST dump of ebpf data
$(OUTPUT)/ebpf_ast.json: client.bpf.c event.h
	$(call msg,DUMP_AST)
	$(Q)$(CLANG) -Xclang -ast-dump=json -I$(OUTPUT) -fsyntax-only client.bpf.c > $(OUTPUT)/event_ast.json

# generate AST dump of ebpf data
$(OUTPUT)/ebpf_btf.json: $(OUTPUT)/client.bpf.o | $(OUTPUT)
	$(call msg,GEN-BTF-DATA,$@)
	$(Q)$(BPFTOOL) btf dump file $< -j > $@

# dump the ebpf program data from build binaries and source
# dump memory layout of ebpf export ring buffer
# add the type info for maps and progs in ebpf program data from source
# generate the final package.json file and check
.PHONY: compile
compile:
	make
	$(call msg,DUMP_LLVM_MEMORY_LAYOUT)
	$(Q) python $(PYTHON_SCRIPTS)/event_mem_layout.py fix_event_c
	$(Q)$(CLANG) -cc1 -fdump-record-layouts-simple $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -emit-llvm -D__TARGET_ARCH_$(ARCH) $(OUTPUT)/rb_export_event.c > $(OUTPUT)/event_layout.txt
	$(Q) python $(PYTHON_SCRIPTS)/event_mem_layout.py > $(OUTPUT)/event_layout.json
	$(call msg,DUMP_EBPF_PROGRAM)
	$(Q)./client $(PACKAGE_NAME) > $(OUTPUT)/ebpf_program_without_type.json
	$(Q)$(OUTPUT)/secgen $(OUTPUT)/client.bpf.o > $(OUTPUT)/ebpf_secdata.json
	$(call msg,FIX_TYPE_INFO_IN_EBPF)
	$(Q) python $(PYTHON_SCRIPTS)/fix_ebpf_program_types.py > $(OUTPUT)/ebpf_program.json
	$(call msg,GENERATE_PACKAGE_JSON)
	$(Q)python $(PYTHON_SCRIPTS)/merge_json_results.py > $(OUTPUT)/package.json
	$(Q)python $(PYTHON_SCRIPTS)/check_is_valid_eunomia_ebpf.py

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

.PHONY: clean_cache
clean_cache:
	$(Q)rm -f $(APPS) $(OUTPUT)/*.json $(OUTPUT)/*.o $(OUTPUT)/*.c $(OUTPUT)/*.h ./*.h ./client.bpf.c
	$(Q)touch ./event.h

.PHONY: build
build:
	$(Q)python ecc.py -d $(SOURCE_DIR) -i $(SOURCE_DIR) $(shell ls $(SOURCE_DIR)*.bpf.c)

.PHONY: docker
docker: wasi-sdk-16.0-linux.tar.gz
	rm -rf eunomia-bpf
	git clone https://github.com/eunomia-bpf/eunomia-bpf  --recursive --depth=1 --shallow-submodules
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
