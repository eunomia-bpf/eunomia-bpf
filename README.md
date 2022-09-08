# eunomia-bpf: A dynamic loader to run CO-RE eBPF as a service

[![Actions Status](https://github.com/eunomia-bpf/eunomia-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/eunomia-bpf/actions)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/eunomia-bpf/eunomia-bpf)](https://github.com/eunomia-bpf/eunomia-bpf/releases)
<!-- [![codecov](https://codecov.io/gh/eunomia-bpf/eunomia-bpf/branch/master/graph/badge.svg)](https://codecov.io/gh/filipdutescu/modern-cpp-template) -->

## Our target: Run <abbr title="Compile Once - Run Everywhere">CO-RE</abbr> eBPF function as a service!

- Run `CO-RE` eBPF code without provisioning or managing infrastructure
- simply requests with a json and run `any` pre-compiled ebpf code on `any` kernel version
- very small and simple! Only a binary about `3MB` and no `LLVM/Clang` dependence
- as fast as `<100ms` to load and run a ebpf program
- `Distributed` and `decentralized`, No remote compile server needed when loading
- Only write Kernel C code which is compatible with `libbpf`

In general, we develop an approach to compile, transmit, and run most libbpf CO-RE objects with some user space config meta data to help us load and operator the eBPF byte code. The compilation and runtime phases of eBPF is separated completely, so, when loading the eBPF program, only the eBPF byte code and a few kB of meta data is needed.

Most of the time, the only thing you need to do is focus on writing a single eBPF program in the kernel. We have a compiler here: [eunomia-cc](https://github.com/eunomia-bpf/eunomia-cc)

## Our function

we have a loader library, a compile toolchain, and some additional tools like cli and Prometheus/OpenTelemetry exporter.

### An eunomia-bpf library

A wrapper of main functions of libbpf, some helper functions for user development.

- provide the ability to load ebpf code to the kernel and run it.
- Use some additional data to help load and config the eBPF bytecode.
- multiple language bindings: see [eunomia-sdks](eunomia-sdks). We have `Rust` now and will add more in the future.

#### Install and Run

To install, just download and use the `binary`:

```bash
$ # download the release from https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli
$ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ecli
```

see [eunomia-bpf](eunomia-bpf) folder for details. With the library, we have provide [a simple cli](https://github.com/eunomia-bpf/eunomia-bpf/releases/), you can simply run pre-compiled ebpf data with a url or path, on most eBPF supported kernel versions:

```bash
$ sudo ./ecli run https://eunomia-bpf.github.io/ebpm-template/package.json # simply run a pre-compiled ebpf code from a url
```

And you can compile and run the program, the only thing you need to do is write the [libbpf kernel C code](bpftools/examples/bootstrap/bootstrap.bpf.c):

```bash
$ docker run -it -v /path/to/repo/bpftools/examples/bootstrap:/src yunwei37/ebpm:latest
$ sudo ./ecli run bpftools/examples/bootstrap/package.json              # run the compiled ebpf code
```

The cli tool can also run as a simple server to receive requests, or as a client to send requests to another server. see [doc/ecli-usage.md](doc/ecli-usage.md) for more usages.

For more examples, see [bpftools/examples](bpftools/examples) directory.

### A compile toolchain for you to generate pre compiled eBPF data

The toolchain can be used as a docker to generate pre-compiled eBPF data in one command:

see the compile toolchains [eunomia-cc](https://github.com/eunomia-bpf/eunomia-cc) for details.

you can also simply use the [ebpm-template](https://github.com/eunomia-bpf/ebpm-template) repo as a template in github, just push to it and github action can help you compile CO-RE ebpf code!

### An Observability tool

An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: [eunomia-exporter](eunomia-exporter)

You can compile it or download from [release](https://github.com/eunomia-bpf/eunomia-bpf/releases/)

#### example

This is an adapted version of opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c), you can check our source code here: [bpftools/examples/opensnoop](bpftools/examples/opensnoop)

After compile the eBPF code, you can define a config file like this:

```yml
programs:
- name: opensnoop
  metrics:
    counters:
    - name: eunomia_file_open_counter
      description: test
      labels:
      - name: pid
      - name: comm
      - name: filename
        from: fname
  compiled_ebpf_filename: bpftools/examples/opensnoop/package.json
```

After start the Prometheus exporter, you can see the metrics like this:

![](doc/images/prometheus.png)

## Road-map

- [X] refactor the code from project `Eunomia` and provide quick examples
- [X] support `tracepoints`, `fentry`, `kprobe`, `lsm`, and `ring buffer` / `perf event` output in userspace.
- [X] make the compile easier to use, and more flexible. Don't need any code modified to compile.
- [X] add configurable exporter
- [ ] use lua for ebpf package load config and add more ebpf support
- [ ] support more ebpf program types:
- [ ] add simple pacakage manager for eunomia-bpf
- [ ] add more possibilities from `libbpf`
- [ ] provide python, go and others sdk
- [ ] add support of `etcd` and enhance server
- [ ] fix ci and docs, multi proto supports

## License

MIT LICENSE