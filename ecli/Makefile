XDG_DATA_HOME ?= ${HOME}/.local/share
EUNOMIA_HOME ?= $(XDG_DATA_HOME)/eunomia

.PHONY: build
build:
	cargo build --release

install:
	rm -rf target/
	cargo build --release
	mkdir -p $(EUNOMIA_HOME)/bin
	install -m 755 ./target/release/ecli-rs $(EUNOMIA_HOME)/bin/ecli

install-deps:
	sudo apt install libssl-dev
	sudo apt install pkg-config
clean:
	cargo clean
