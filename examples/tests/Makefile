TEST_EXAMPLE_DIR ?= ../bpftools/
TEST_TIME ?= 2
ECLI_DIR ?= ../../ecli/
ECC_DIR ?= ../../compiler/
ECC_BIN ?= ../../compiler/workspace/bin/ecc

# TODO: maybe use the compile docker to test?

.PHONY:test test_project install-deps clean
all: test

install-deps:
	make -C $(ECC_DIR) install-deps
	make -C $(ECC_DIR)
	make -C $(ECC_DIR) install
	make -C $(ECLI_DIR) install
	cp $(ECLI_DIR)target/release/ecli ./ecli

# test with the files in bpf-loader
TEST_CASES_DIRS=$(shell ls -l $(TEST_EXAMPLE_DIR) | grep ^d | awk '{print $$9}')
test: $(TEST_CASES_DIRS)

.PHONY:$(TEST_CASES_DIRS)
# build the test cases
$(TEST_CASES_DIRS):install-deps
	ls $(TEST_EXAMPLE_DIR)$@/$@.h && $(ECC_BIN) $(TEST_EXAMPLE_DIR)$@/$@.bpf.c $(TEST_EXAMPLE_DIR)$@/$@.h \
	|| $(ECC_BIN) $(TEST_EXAMPLE_DIR)$@/$@.bpf.c
	sudo timeout --preserve-status -s 2 $(TEST_TIME) ./ecli run $(TEST_EXAMPLE_DIR)$@/package.json

install-wasm-clang: ## install clang for wasm
	wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-16/wasi-sdk-16.0-linux.tar.gz
	tar -zxf wasi-sdk-16.0-linux.tar.gz && mkdir /opt/wasi-sdk/ && mv wasi-sdk-16.0/* /opt/wasi-sdk/

clean:
	@make -C client clean
