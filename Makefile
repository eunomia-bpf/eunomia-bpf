.PHONY: ecli bpf-loader eunomia-exporter help install-deps clean ewasm all
.DEFAULT_GOAL := all
all: bpf-loader ewasm ecli ## Build all binaries

define BROWSER_PYSCRIPT
import os, webbrowser, sys

try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"
INSTALL_LOCATION := ~/.local

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

install-deps: ## install deps
	apt update
	apt-get install libcurl4-openssl-dev libelf-dev clang llvm cmake zlib1g-dev

ecli: ## build the command line tool for eunomia-bpf
	make -C ecli/minimal install

ewasm: ## build the command line tool for eunomia-bpf
	make -C wasm-runtime build

bpf-loader: ## build the core library for eunomia-bpf
	make -C bpf-loader

ecc: ## build the core library for eunomia-bpf
	make -C compiler

clean: ## clean all build projects
	make -C bpf-loader clean
	make -C ecli/minimal clean

eunomia-exporter: ## build the exporter for custom metric
	make -C bpf-loader
	cd eunomia-exporter && cargo build --release

release:
	make -C ecli/minimal install
	make -C compiler install
	cp -R ~/.eunomia .eunomia
	tar -czvf eunomia.tar.gz .eunomia
	rm -rf .eunomia