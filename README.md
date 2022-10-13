# eunomia-bpf: An eBPF program Dynamic Loading Framework

[![Actions Status](https://github.com/eunomia-bpf/eunomia-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/eunomia-bpf/actions)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/eunomia-bpf/eunomia-bpf)](https://github.com/eunomia-bpf/eunomia-bpf/releases)
<!-- [![codecov](https://codecov.io/gh/eunomia-bpf/eunomia-bpf/branch/master/graph/badge.svg)](https://codecov.io/gh/filipdutescu/modern-cpp-template) -->

## Overview

`eunomia-bpf` is a dynamic loading library base on `libbpf`, and a compile toolchain. With eunomia-bpf, you can:

- Write eBPF kernel code only and automatically exposing your data from kernel
- Compile eBPF kernel code to a `JSON`, you can dynamically load it on another machine without recompile
- Compile eBPF program to a `WASM` module, and you can operate the eBPF program or process the data in user space `WASM` runtime
- Package, distribute, and run user-space and kernel-space eBPF programs together in `WASM` module
- very small and simple! The library itself `<1MB` and no `LLVM/Clang` dependence, can be embedded easily in you project
- as fast as `<100ms` and little resource need to dynamically load and run eBPF program

With `eunomia-bpf`, you can also get pre-compiled eBPF programs running from the cloud to the kernel in `1` line of bash, kernel version and architecture independent!

## Project Arch

we have a loader library, a compile toolchain, and some additional tools like cli and a custom metrics exporter.

![eunomia-arch.png](documents/images/eunomia-arch.png)

### An eunomia-bpf library

A wrapper of main functions of libbpf, provide the ability to dynamically load eBPF code to the kernel and run it with a simple JSON and a few API.

see [eunomia-bpf](eunomia-bpf) for details.

A [simple cli interface](ecli) is provided for eunomia-bpf library, which you can use it to start any eBPF program from a url in a command. You can download it from [release](https://github.com/eunomia-bpf/eunomia-bpf/releases/) for example:

```bash
# download the release from https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli
$ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
$ sudo ./ecli run https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/package.json # simply run a pre-compiled ebpf code from a url
```

Or you can write eBPF kernel code only and compile it to a `JSON`:

```bash
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

see [examples](examples) for more examples.

### A library to load eBPF program from a WASM module

Use the `eunomia-bpf` library to load `eBPF` program from a `WASM` module, you can write a WASM module to operate the eBPF program or process the data in user space `WASM` runtime. The idea is simple:

1. compile the kernel eBPF code skeleton to the `JSON` format with `eunomia-cc` toolchain
2. embed the `JSON` data in the `WASM` module, and provide some API for operating the eBPF program skeleton
3. load the `JSON` data from the `WASM` module and run the eBPF program skeleton with `eunomia-bpf` library

You can have multiple `eBPF` program in a single `WASM` module.

See [ewasm](ewasm) for details. For example, you can run an eBPF program with a WASM module for an URL:

```bash
$ sudo ./ecli run https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/app.wasm
```

You can also generate a WASM program template for eBPF or build WASM module with `eunomia-cc` container:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest gen-wasm-skel # generate WASM app template for eBPF
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest build-wasm    # Build WASM module
```

see [sigsnoop example](examples/bpftools/sigsnoop) for more detail.

### A compile toolchain to help you generate pre compiled eBPF data

The toolchain can be used as a docker to generate pre-compiled eBPF data in one command:

see the compile toolchains [eunomia-cc](https://github.com/eunomia-bpf/eunomia-cc) for details.

you can also simply use the [ebpm-template](https://github.com/eunomia-bpf/ebpm-template) repo as a template in github, just push to it and github action can help you compile CO-RE ebpf code!

### An Observability tool

An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: [eunomia-exporter](eunomia-exporter)

You can compile it or download from [release](https://github.com/eunomia-bpf/eunomia-bpf/releases/)

### other related projects

- LMP eBPF Hub: [github.com/linuxkerneltravel/lmp](https://github.com/linuxkerneltravel/lmp) 

    > a package manager for eBPF based on wasm modules

- bolipi online compiler & runner: [https://bolipi.com/ebpf/home/online](https://bolipi.com/ebpf/home/online)

    > an online compiler and runner for eBPF program newbies

## build the project

see [build](documents/build.md) for details.

## examples

see [examples](examples) for details about eBPF tools and library usage.

We also have a prove of concept video: [Writing eBPF programs in WASM](https://www.bilibili.com/video/BV1JN4y1A76k/).

## benchmark

see [benchmark](documents/benchmark.md) for details.

## Road-map

- [X] refactor the code from project `Eunomia` and provide quick examples
- [X] support `tracepoints`, `fentry`, `kprobe`, `lsm`, and `ring buffer` / `perf event` output in userspace.
- [X] make the compile easier to use, and more flexible. Don't need any code modified to compile.
- [X] add configurable exporter as an example
- [X] add simple pacakage manager for eunomia-bpf: in [LMP](https://github.com/linuxkerneltravel/lmp) community
- [X] use WASM for ebpf package load config and add more user space support
- [ ] support more ebpf program types: uprobe, xdp etc.
- [ ] add more possibilities and helper functions from `libbpf`
- [ ] Android support
- [ ] provide python, go and others sdk
- [ ] add support of `etcd` and enhance server

## License

MIT LICENSE
