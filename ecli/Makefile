
.PHONY: build
build:
	cargo build --release

install:
	rm -rf target/
	cargo build --release
	rm -rf ~/.eunomia
	mkdir -p ~/.eunomia/bin
	cp ./target/release/ecli-rs ~/.eunomia/bin/ecli

install-deps:
	sudo apt install libssl-dev
	sudo apt install pkg-config
