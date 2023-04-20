
.PHONY: build
build:
	cargo build --release

install:
	rm -rf target/
	cargo build --release
	mkdir -p ~/.eunomia/bin
	cp ./target/release/ecli ~/.eunomia/bin/ecli

install-deps:
	sudo apt install libssl-dev
	sudo apt install pkg-config