build: install-deps
	cargo build --release

build-debug: install-deps
	cargo build

test: build-debug
	cargo test

install-deps:
	sudo apt-get update 
	sudo apt install libelf-dev zlib1g-dev -y

clean:
	cargo clean
