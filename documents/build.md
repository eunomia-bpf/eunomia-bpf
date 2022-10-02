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

## build eunomia-bpf

eunomia-bpf is our core library written in C++17. It has no other dependencies except libbpf.

```shell
$ git submodule update --init --recursive       # check out libbpf
$ make eunomia-bpf                              # build eunomia-bpf
```

The recommended compiler is gcc9 or later.

## build ecli:

After compile the eunomia-bpf, you can build the cli tool in C++:

```shell
$ make ecli
```

reference: https://github.com/libbpf/libbpf-bootstrap

## build eunomia-exporter

The eunomia-exporter is written in Rust, you need to install the toolchain first. And you need to compile the `eunomia-bpf` library, which will be statically linked to the exporter.

then you can build the exporter:

```shell
$ make eunomia-exporter
```

## build wasm lib

Please install WASI SDK, download the [wasi-sdk](https://github.com/CraneStation/wasi-sdk/releases) release and extract the archive to default path /opt/wasi-sdk.

## more details


- You can check the Makefile at project root for more details: [Makefile](../Makefile)
- You may want to refer to our CI for more build info: [.github/workflowsubuntu.yml](../.github/workflows/ubuntu.yml)