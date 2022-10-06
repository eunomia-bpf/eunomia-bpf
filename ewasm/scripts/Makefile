BUILD_DIR ?= ../build-wasm
$(SOURCE_DIR) ?= .

define GENERATE_HEADER_PYSCRIPT
header = """
// auto generated. do not edit.
#ifndef EWASM_JSON_INCLUDE_H_
#define EWASM_JSON_INCLUDE_H_
char* program_data = """
base = """;
#endif
"""
ebpf_program_data = "package.json"
ebpf_program_header = "ewasm-skel.h"

import json
from os.path import exists

if not exists(ebpf_program_data):
	# ignore for building without package.json
	exit(0)

d = {}

with open(ebpf_program_data) as f:
    data = f.read()
    d["a"] = data
    f.close()

# generate header include for wasm module
with open (ebpf_program_header, "w") as f:
    jstr = json.dumps(d)
    jstr = jstr[5:]
    jstr = jstr[:-1]
    header_str = header + jstr + base
    f.write(header_str)
    f.close()
endef
export GENERATE_HEADER_PYSCRIPT

.PHONY: all build generate

all: build
build:
	@cd $(SOURCE_DIR) && python -c "$$GENERATE_HEADER_PYSCRIPT"
	@rm -rf $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)
	@cp -r $(SOURCE_DIR)/* $(BUILD_DIR)
	@cp ./build.sh $(BUILD_DIR)
	cd $(BUILD_DIR) && ./build.sh
	@cp $(BUILD_DIR)/*.wasm $(SOURCE_DIR)

generate:
	@cd $(SOURCE_DIR) && python -c "$$GENERATE_HEADER_PYSCRIPT"
	@mkdir -p $(SOURCE_DIR)/eunomia-include
	@cp -r ../include/wasm-app/* $(SOURCE_DIR)/eunomia-include
	@cp template/* $(SOURCE_DIR) && chmod -R 777 $(SOURCE_DIR)
