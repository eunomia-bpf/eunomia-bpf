TEST_EXAMPLE_DIR ?= ../examples/execsnoop/
TEST_TIME ?= 4
ECLI_DIR ?= ../../ecli/

# TODO: maybe use the compile docker to test?

.PHONY:test test_project clone_and_install_deps clean
all: test

test_project:
	SOURCE_DIR=../$(TEST_EXAMPLE_DIR) make -C eunomia-cc build
	sudo timeout --preserve-status -s 2 $(TEST_TIME) ./ecli run $(TEST_EXAMPLE_DIR)package.json

clone_and_install_deps:
	rm -rf ./eunomia-cc ./ecli
	git clone https://github.com/eunomia-bpf/eunomia-cc --recursive 	# checkout the newest toolchain
	make -C eunomia-cc
	make -C $(ECLI_DIR) install
	cp $(ECLI_DIR)build/bin/Release/ecli ./ecli

test:
	make test_project TEST_EXAMPLE_DIR=../examples/bootstrap/
	make test_project TEST_EXAMPLE_DIR=../examples/minimal/
	make test_project TEST_EXAMPLE_DIR=../examples/kprobe-link/
	make test_project TEST_EXAMPLE_DIR=../examples/fentry-link/
	make test_project TEST_EXAMPLE_DIR=../examples/opensnoop/
	make test_project TEST_EXAMPLE_DIR=../examples/bindsnoop/
	make test_project TEST_EXAMPLE_DIR=../examples/sigsnoop/
	make test_project TEST_EXAMPLE_DIR=../examples/mountsnoop/
	make test_project TEST_EXAMPLE_DIR=../examples/tcpconnlat/

clean:
	@make -C client clean
