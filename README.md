# eunomia-bpf: eBPF as a service

[![Actions Status](https://github.com/eunomia-bpf/eunomia-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/eunomia-bpf/actions)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/eunomia-bpf/eunomia-bpf)](https://github.com/eunomia-bpf/eunomia-bpf/releases)
<!-- [![codecov](https://codecov.io/gh/eunomia-bpf/eunomia-bpf/branch/master/graph/badge.svg)](https://codecov.io/gh/filipdutescu/modern-cpp-template) -->

## Our target: Run <abbr title="Compile Once - Run Everywhere">CO-RE</abbr> eBPF function as a service!

- Run `CO-RE` eBPF code without provisioning or managing infrastructure
- simply requests with a json and run `any` pre-compiled ebpf code on `any` kernel version
- very small and simple! Only a binary about `3MB`
- as fast as `100ms` to load and run a ebpf program
- `Distributed` and `decentralized`, No compile helper server

In general, we develop an approach to compile, transmit, and run most libbpf CO-RE objects with some user space config meta data to help us load and operator the eBPF byte code.

So, the only thing you need to do is focus on writing a single eBPF program in the kernel. We have a compiler here: [eunomia-cc](https://github.com/eunomia-bpf/eunomia-cc)

## Our function

we have these parts:

### An eunomia-bpf library

A wrapper of main functions of libbpf, some helper functions for user development.

- provide the ability to load ebpf code to the kernel and run it.
- Use some additional data to help load and config the eBPF bytecode.
- multiple language bindings: see [eunomia-sdks](eunomia-sdks)

#### Install and Run

To install, just download and use the `binary`:

```bash
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ecli
```

see [eunomia-bpf](eunomia-bpf) folder for details. With the library, we have provide [a simple cli](https://github.com/eunomia-bpf/eunomia-bpf/releases/), you can simply run pre-compiled ebpf data with a url or path, on most eBPF supported kernel versions:

```bash
$ sudo ./ecli run https://gitee.com/yunwei37/eunomia-bpf/raw/master/bpftools/examples/package.json
$ sudo ./ecli run bpftools/examples/package.json

$ sudo ./ecli server # run as a simple server
```

The cli tool can also run as a simple server to receive requests, or as a client to send requests to another server. see [doc/ecli-usage.md](doc/ecli-usage.md) for more usages.

### A compile toolchain for you to generate pre compiled eBPF data

The toolchain can be used as a docker to generate pre-compiled eBPF data in one command:

see the compile toolchains [eunomia-cc](https://github.com/eunomia-bpf/eunomia-cc) for details.

you can also simply use the [ebpm-template](https://github.com/eunomia-bpf/ebpm-template) repo as a template in github, just push to it and github action can help you compile CO-RE ebpf code!

## An Observability tool

An observability tool use eBPFm with prometheus and OpenTelemetry exporter: [eunomia-exporter](eunomia-exporter)

### An ebpf package manager: ebpm

see https://github.com/eunomia-bpf/ebpm for details.

## Road-map

- [X] refactor the code from project `Eunomia` and provide quick examples
- [X] support `tracepoints`, `fentry`, `kprobe`, `lsm`, and `ring buffer` / `perf event` output in userspace.
- [X] make the compile easier to use, and more flexible. Don't need any code modified to compile.
- [ ] use lua for ebpf package load config and add more ebpf support
- [ ] support more ebpf program types:
- [ ] add more possibilities from `libbpf`
- [ ] provide python, go and others sdk
- [ ] add configurable exporter
- [ ] add support of `etcd` and enhance server
- [ ] fix ci and docs, multi proto supports

## License

MIT LICENSE