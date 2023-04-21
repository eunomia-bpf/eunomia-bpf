# build

If you want to run the cli, in most cases, you don't need to build your own.

# Building

libbpf-bootstrap supports multiple build systems that do the same thing.
This serves as a cross reference for folks coming from different backgrounds.

## Install Dependencies

You will need `clang`, `libelf` and `zlib` to build the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

install rust toolchain

```shell
curl https://sh.rustup.rs -sSf | sh -s
```

## build bpf-loader-rs

bpf-loader-rs is our core library written in Rust.

```shell
$ make bpf-loader-rs  #build ebpf-loader-rs
```

The recommended compiler is gcc9 or later.

## build ecli:

After compile the bpf-loader, you can build the cli tool in C++:

```shell
$ make ecli
```

reference: https://github.com/libbpf/libbpf-bootstrap

## build compiler

```shell
$ make ecc
```
## more details

- You can check the Makefile at project root for more details: [Makefile](../Makefile)
- You may want to refer to our CI for more build info: [.github/workflowsubuntu.yml](../.github/workflows/ubuntu.yml)
