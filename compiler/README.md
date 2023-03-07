# The eBPF compile toolchain for eunomia-bpf

An CO-RE compile set to help you focus on writing a single eBPF program in the kernel. Nothing more TODO!

- note this is not a template for new eunomia-bpf projects, You may find the [eunomia-bpf-template](https://github.com/eunomia-bpf/ebpm-template) there.
- This repo will focus on the compile of eBPF programs. For runtime, please see: [github.com/eunomia-bpf/eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf)

## Usage

For the detail usage, please refer to [https://eunomia-bpf.github.io/ecc/usage.html](https://eunomia-bpf.github.io/ecc/usage.html)

## Building

This repo use the similar structs as libbpf-bootstrap.

libbpf-bootstrap supports multiple build systems that do the same thing.
This serves as a cross reference for folks coming from different backgrounds.

### Install Dependencies

You will need `clang`, `libelf` and `zlib` to build the examples, package names may vary across distros. `Rust` and `Cargo` are also required.

On Ubuntu/Debian, you need:

```shell
apt install clang libelf1 libelf-dev zlib1g-dev llvm
```

On CentOS/Fedora, you need:

```shell
dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

### Build locally

Makefile build the toolchain:

```shell
git submodule update --init --recursive --remote       # check out libbpf
make
make install
export PATH=$PATH:~/.eunomia/bin
```

After the toolchain has been build, run:

```console
$ ecc -h
eunomia-bpf compiler

Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]
```

For example, to compile `cmd/test/client.bpf.c` and export the event header with `cmd/test/client.bpf.h`:

```console
ecc cmd/test/client.bpf.c cmd/test/event.h
```

create `package.json` for packing the object and config file:

```console
ecc cmd/test/client.bpf.c cmd/test/event.h
```

Or you may use the make file:

```shell
SOURCE_DIR=[target dir] make build
```

### build docker image

```shell
make docker
```

## Road-map

- [X] support `tracepoints`, `fentry`, `kprobe`, `lsm`, and `ring buffer` / `perf event` output in userspace.
- [X] make the compile easier to use, and more flexible. Don't need any code modified to compile.
- [ ] add more ebpf program type support: `xdp`, `perf event` and `uprobe`
- [X] add Wasm support
- [X] redesign the JSON
- [X] add more possibilities from `libbpf`
- [ ] provide better support for old kernels

## License

MIT LICENSE
