# eunomia-bpf: A Dynamic Loading Framework for CO-RE eBPF program with WASM

[![Actions Status](https://github.com/eunomia-bpf/eunomia-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/eunomia-bpf/actions)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/eunomia-bpf/eunomia-bpf)](https://github.com/eunomia-bpf/eunomia-bpf/releases)
<!-- [![codecov](https://codecov.io/gh/eunomia-bpf/eunomia-bpf/branch/master/graph/badge.svg)](https://codecov.io/gh/filipdutescu/modern-cpp-template) -->

## Our target

- Run `CO-RE` eBPF code without provisioning or managing infrastructure
- simply requests with a json and run `any` pre-compiled ebpf code on `any` kernel version
- very small and simple! Only about `3MB` and no `LLVM/Clang` dependence, can be embedded easily
- Provide a custom eBPF metrics exporter to `Prometheus` or `OpenTelemetry` in async rust
- as fast as `<100ms` to dynamically load and run any eBPF program, much more faster than `bcc`
- Only write Kernel C code which is compatible with `libbpf`, or use WASM for processing data

In general, we develop an approach to compile, transmit, and run most libbpf CO-RE objects with some user space config meta data to help you load and operator the eBPF byte code. The compilation and runtime phases of eBPF is separated completely, so, when loading the eBPF program, only the eBPF byte code and a few kB of meta data is needed.

Most of the time, the only thing you need to do is focus on writing a single eBPF program in the kernel.

## Project Arch

we have a loader library, a compile toolchain, and some additional tools like cli and Prometheus/OpenTelemetry exporter.

### An eunomia-bpf library

A wrapper of main functions of libbpf, provide the ability to dynamically load eBPF code to the kernel and run it with a simple JSON and a few API.

see [eunomia-bpf](eunomia-bpf) for details.

A [simple cli interface](ecli) is provided for eunomia-bpf library, which you can use it to start any eBPF program from a url in a command, for example:

```bash
$ sudo ecli run https://eunomia-bpf.github.io/ebpm-template/package.json # simply run a pre-compiled ebpf code from a url
```

### A compile toolchain for you to generate pre compiled eBPF data

The toolchain can be used as a docker to generate pre-compiled eBPF data in one command:

see the compile toolchains [eunomia-cc](https://github.com/eunomia-bpf/eunomia-cc) for details.

you can also simply use the [ebpm-template](https://github.com/eunomia-bpf/ebpm-template) repo as a template in github, just push to it and github action can help you compile CO-RE ebpf code!

### An Observability tool

An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: [eunomia-exporter](eunomia-exporter)

You can compile it or download from [release](https://github.com/eunomia-bpf/eunomia-bpf/releases/)

### other related projects

- LMP eBPF Hub: [github.com/linuxkerneltravel/lmp](https://github.com/linuxkerneltravel/lmp)
- bolipi online compiler & runner: [https://bolipi.com/ebpf/home/online](https://bolipi.com/ebpf/home/online)

## Road-map

- [X] refactor the code from project `Eunomia` and provide quick examples
- [X] support `tracepoints`, `fentry`, `kprobe`, `lsm`, and `ring buffer` / `perf event` output in userspace.
- [X] make the compile easier to use, and more flexible. Don't need any code modified to compile.
- [X] add configurable exporter as an example
- [X] add simple pacakage manager for eunomia-bpf: in [LMP](https://github.com/linuxkerneltravel/lmp) community
- [ ] use WASM for ebpf package load config and add more user space support
- [ ] support more ebpf program types: uprobe, xdp etc.
- [ ] add more possibilities and helper functions from `libbpf`
- [ ] provide python, go and others sdk
- [ ] add support of `etcd` and enhance server

## License

MIT LICENSE
