
# test with the files in eunomia-bpf
TEST_CASES_DIRS=$(shell ls -l eunomia-bpf/examples/bpftools | grep ^d | awk '{print $$9}')
.PHONY: test
test:
	rm -rf eunomia-bpf/
	git clone https://github.com/eunomia-bpf/eunomia-bpf --depth 1
	$(MAKE) $(TEST_CASES_DIRS)

$(TEST_CASES_DIRS):
	@echo $@
	SOURCE_DIR=libs/tests/eunomia-bpf/examples/bpftools/$@/ $(MAKE) -C ../../ build
