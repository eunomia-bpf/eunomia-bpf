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

You will need `clang`, `libelf` and `zlib` to build the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev llvm python
```

On CentOS/Fedora, you need:

```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

### Build locally

Makefile build the toolchain:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ make
```

After the toolchain has been build, run:

```shell
$ python ecc.py [you file to compile]
```

or

```shell
SOURCE_DIR=[target dir] make build
```

to compile it.

### build docker image

```shell
make docker
```

## Road-map

- [X] support `tracepoints`, `fentry`, `kprobe`, `lsm`, and `ring buffer` / `perf event` output in userspace.
- [X] make the compile easier to use, and more flexible. Don't need any code modified to compile.
- [ ] add more ebpf program type support: `xdp`, `perf event` and `uprobe`
- [X] add WASM support
- [ ] redesign the JSON
- [ ] add more possibilities from `libbpf`
- [ ] provide better support for old kernels

## License

MIT LICENSE
