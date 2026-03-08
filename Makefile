.PHONY: ecli bpf-loader-rs eunomia-exporter help install-deps clean all release
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
	apt-get install libcurl4-openssl-dev libelf-dev clang llvm cmake zlib1g-dev libzstd-dev liblzma-dev pkg-config

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
EUNOMIA_HOME ?= $(XDG_DATA_HOME)/eunomia

release:
	@set -eu; \
	staging_root="$$(mktemp -d)"; \
	release_root="$$(mktemp -d ./.eunomia.release.XXXXXX)"; \
	previous_root=""; \
	previous_archive=""; \
	runtime_promoted=0; \
	release_live=0; \
	cleanup() { \
		status=$$?; \
		set +e; \
		if [ $$status -ne 0 ] && [ "$$release_live" -eq 0 ]; then \
			if [ "$$runtime_promoted" -eq 1 ] && [ -e eunomia ]; then \
				rm -rf eunomia; \
			fi; \
			if [ -n "$$previous_root" ] && [ -e "$$previous_root" ]; then \
				mv "$$previous_root" eunomia; \
				previous_root=""; \
			fi; \
			if [ -e eunomia.tar.gz ] && [ -n "$$previous_archive" ] && [ -e "$$previous_archive" ]; then \
				rm -f eunomia.tar.gz; \
			fi; \
			if [ -n "$$previous_archive" ] && [ -e "$$previous_archive" ]; then \
				mv "$$previous_archive" eunomia.tar.gz; \
				previous_archive=""; \
			fi; \
		fi; \
		rm -rf "$$staging_root" "$$release_root"; \
		if [ $$status -ne 0 ] && [ "$$release_live" -eq 1 ] && [ -n "$$previous_archive" ] && [ -e "$$previous_archive" ]; then \
			if rm -f "$$previous_archive"; then previous_archive=""; fi; \
		fi; \
		if [ $$status -ne 0 ] && [ "$$release_live" -eq 1 ] && { [ -n "$$previous_root" ] || [ -n "$$previous_archive" ]; }; then \
			printf '%s\n' "release installed, but backup cleanup failed; inspect lingering .eunomia.previous* artifacts" >&2; \
		fi; \
		exit $$status; \
	}; \
	trap cleanup EXIT; \
	stage_home="$$staging_root/eunomia"; \
	$(MAKE) -C ecli install EUNOMIA_HOME="$$stage_home"; \
	$(MAKE) -C compiler install EUNOMIA_HOME="$$stage_home"; \
	cp -R "$$stage_home" "$$release_root/eunomia"; \
	tar -czvf "$$release_root/eunomia.tar.gz" -C "$$release_root" eunomia; \
	if [ -e eunomia ]; then previous_root="$$(mktemp -d ./.eunomia.previous.XXXXXX)"; rmdir "$$previous_root"; mv eunomia "$$previous_root"; fi; \
	mv "$$release_root/eunomia" eunomia; \
	runtime_promoted=1; \
	if [ -e eunomia.tar.gz ]; then archive_backup_path="$$(mktemp ./.eunomia.previous.tar.gz.XXXXXX)"; rm -f "$$archive_backup_path"; mv eunomia.tar.gz "$$archive_backup_path"; previous_archive="$$archive_backup_path"; fi; \
	mv "$$release_root/eunomia.tar.gz" eunomia.tar.gz; \
	release_live=1; \
	if [ -n "$$previous_root" ]; then rm -rf "$$previous_root"; previous_root=""; fi; \
	if [ -n "$$previous_archive" ]; then rm -f "$$previous_archive"; previous_archive=""; fi
