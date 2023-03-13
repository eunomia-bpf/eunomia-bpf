LIBEUNOMIA := ../bpf-loader/build/lib/Release/libeunomia.a

.PHONY: build
build: $(LIBEUNOMIA)
	cargo build --release

$(LIBEUNOMIA):
	$(MAKE) -C ../bpf-loader install

install: $(LIBEUNOMIA) ## install the package to the `INSTALL_LOCATION`
	rm -rf target/
	cargo build --release --config net.git-fetch-with-cli=true
	mkdir -p ~/.eunomia/bin
	cp ./target/release/ecli ~/.eunomia/bin/ecli

install-deps:
	sudo apt install libssl-dev
	sudo apt install pkg-config
