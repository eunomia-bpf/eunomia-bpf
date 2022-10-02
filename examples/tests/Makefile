TEST_EXAMPLE_DIR ?= ../bpftools/
TEST_TIME ?= 4
ECLI_DIR ?= ../../ecli/

# TODO: maybe use the compile docker to test?

.PHONY:test test_project clone_and_install_deps clean
all: test

clone_and_install_deps:
	rm -rf ./eunomia-cc ./ecli
	git clone https://github.com/eunomia-bpf/eunomia-cc --recursive --depth=1 --shallow-submodules	# checkout the newest toolchain
	make -C eunomia-cc
	make -C $(ECLI_DIR) install
	cp $(ECLI_DIR)build/bin/Release/ecli ./ecli

# test with the files in eunomia-bpf
TEST_CASES_DIRS=$(shell ls -l $(TEST_EXAMPLE_DIR) | grep ^d | awk '{print $$9}')
test: $(TEST_CASES_DIRS)

.PHONY:$(TEST_CASES_DIRS)
# build the test cases
$(TEST_CASES_DIRS):
	SOURCE_DIR=../$(TEST_EXAMPLE_DIR)$@/ make -C eunomia-cc build
	sudo timeout --preserve-status -s 2 $(TEST_TIME) ./ecli run $(TEST_EXAMPLE_DIR)$@/package.json

clean:
	@make -C client clean
