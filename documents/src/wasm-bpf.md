# 📦 Wasm-bpf: Wasm library and toolchain for eBPF

[![Actions Status](https://github.com/eunomia-bpf/wasm-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/wasm-bpf/actions)
[![CodeFactor](https://www.codefactor.io/repository/github/eunomia-bpf/wasm-bpf/badge)](https://www.codefactor.io/repository/github/eunomia-bpf/wasm-bpf)
[![DeepSource](https://deepsource.io/gh/eunomia-bpf/wasm-bpf.svg/?label=active+issues&show_trend=true&token=rcSI3J1-gpwLIgZWtKZC-N6C)](https://deepsource.io/gh/eunomia-bpf/wasm-bpf/?ref=repository-badge)

[中文文档](https://github.com/eunomia-bpf/wasm-bpf/tree/main/README_zh.md) [Gitee](https://gitee.com/eunomia-bpf/wasm-bpf) [Github](https://github.com/eunomia-bpf/wasm-bpf)

`Wasm-bpf` is a WebAssembly eBPF library, toolchain and runtime powered by [CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)(Compile Once – Run Everywhere) [libbpf](https://github.com/libbpf/libbpf). It can help you build almost every eBPF programs or usecases to `Wasm` with nearly zero modification, and run them cross platforms with Wasm sandbox.

## Introduction

`WebAssembly` (Wasm) is a portable binary format for executable code. The code is executed at a nearly-native speed in a memory-safe (for host) sandbox, with clearly defined resource constraints, and APIs for communicating with the embedding host environment (eg. proxy).The `wasm-bpf` project combines Wasm and eBPF technologies to enhance the performance and programmability of eBPF applications.

With `wasm-bpf`, users can dynamically load and securely execute user-defined or community-contributed Wasm-eBPF codes as `plug-ins` in their software products, such as observability platforms or service proxy. This enables efficient and scalable data collection, while also allowing for advanced processing and analysis of that data.

It also enables developers to write eBPF programs in familiar languages like `C/C++`, `Rust`, `Go`, and more than 30 other programming languages, and deploy them easily across different Linux distributions. Additionally, cloud providers can leverage wasm-bpf to offer a `secure` and `high-performance` environment for their customers to develop and deploy eBPF applications in their cloud environments.

## Features

- **`General purpose`**: provide most abilities from eBPF to Wasm, `polling` from the ring buffer or perf buffer, bidirectional communications between `kernel` eBPF and `userspace` Wasm using `maps`, dynamically `loading`, `attaching` or `detaching`, etc. Supports a large number of eBPF program types and map types.
- **`High performance`**: No `serialization` overhead for complex data types, using `shared memory` to avoid copy overhead between host and Wasm.
- **`Easy to use`**: provide a similar developing experience as the [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap), `auto generate` the Wasm-eBPF skeleton headers and type definitions for bindings. Write your eBPF programs in `C/C++`, `Rust`, `Go` and compile to Wasm.
- **`Ultralightweight`**: the miminal runtime has only `1.5 MB` in binary size. Compiled Wasm module would be only `~90K`. With the same toolchain, you can easily build your own Wasm-eBPF runtime in any languages and platforms!

See the [examples](https://github.com/eunomia-bpf/wasm-bpf/tree/main/examples) directory for examples of eBPF programs written in C, Rust, Go and compiled to Wasm, covering the use cases from `tracing`, `networking` to `security`.

For tools to distribute Wasm-eBPF programs in [`OCI`](https://opencontainers.org/) images, please refer to [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) repo.
