---
weight: 3
bookCollapseSection: false
title: "Project architecture"
---

# Project Architecture

we have a loader library, a compile toolchain, and some additional tools like cli and a custom metrics exporter.

![eunomia-arch.png](../img/eunomia-arch.png)

## An bpf-loader-rs library

A wrapper of main functions of libbpf-rs, provide the ability to dynamically load eBPF code to the kernel and run it with a simple JSON and a few API.

see [bpf-loader-rs](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/bpf-loader-rs) for details.

A [simple cli interface](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/ecli) is provided for bpf-loader library, which you can use it to start any eBPF program from a url in a command. You can download it from [release](https://github.com/eunomia-bpf/eunomia-bpf/releases/).

see [examples](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples) for more examples.

## A library to load and operate eBPF program from a WASM module

Use the `eunomia-bpf` library to load `eBPF` program from a `WASM` module, you can write a WASM module to operate the eBPF program or process the data in user space `WASM` runtime. The idea is simple:

1. compile the kernel eBPF code skeleton to the `JSON` format with `eunomia-cc` toolchain
2. embed the `JSON` data in the `WASM` module, and provide some API for operating the eBPF program skeleton
3. load the `JSON` data from the `WASM` module and run the eBPF program skeleton with `eunomia-bpf` library

You can have multiple `eBPF` program in a single `WASM` module.

See [wasm-runtime](https://github.com/eunomia-bpf/wasm-bpf) for details. In fact, `wasm-bpf` library only exports a few functions from `bpf-loader` library to the `VM`, so you can replace the `WASM` runtime with your own easily.

For example, you can run an eBPF program with a WASM module for an URL:

```bash
sudo ./ecli run https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/app.wasm
```

You can also generate a WASM program template for eBPF or build WASM module with `compiler` container:

```shell
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest gen-wasm-skel # generate WASM app template for eBPF
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest build-wasm    # Build WASM module
```

see [sigsnoop example](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/sigsnoop) for more detail.

## A compile toolchain to help you generate pre compiled eBPF data

The toolchain can be used as a docker to generate pre-compiled eBPF data in one command:

see the compile toolchains [compiler](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/compiler) for details.

you can also simply use the [ebpm-template](https://github.com/eunomia-bpf/ebpm-template) repo as a template in github, just push to it and github action can help you compile CO-RE ebpf code!

## other related projects

- LMP eBPF Hub: [github.com/linuxkerneltravel/lmp](https://github.com/linuxkerneltravel/lmp)

    > a package manager for eBPF based on wasm modules

- bolipi online compiler & runner: [https://bolipi.com/ebpf/home/online](https://bolipi.com/ebpf/home/online)

    > an online compiler and runner for eBPF program newbies

- An Observability tool

    > An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: [eunomia-exporter](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/eunomia-sdks/eunomia-otel). You can compile it or download from [release](https://github.com/eunomia-bpf/eunomia-bpf/releases/)
