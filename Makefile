.PHONY: ecli bpf-loader-rs eunomia-exporter help install-deps clean all
.DEFAULT_GOAL := all
all: bpf-loader-rs ecli ## Build all binaries

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
	make -C ecli build

bpf-loader-rs: ## build the core library for eunomia-bpf
	make -C bpf-loader-rs

ecc: ## build the core library for eunomia-bpf
	make -C compiler

clean: ## clean all build projects
	make -C bpf-loader-rs clean
	make -C ecli clean
	make -C examples clean
eunomia-exporter: ## build the exporter for custom metric
	make -C bpf-loader-rs
	cd eunomia-exporter && cargo build --release

XDG_DATA_HOME ?= ${HOME}/.local/share
EUNOMIA_HOME := $(XDG_DATA_HOME)/eunomia

release:
	make -C ecli install
	make -C compiler install
	cp -R $(EUNOMIA_HOME) eunomia
	tar -czvf eunomia.tar.gz eunomia
	rm -rf eunomia
