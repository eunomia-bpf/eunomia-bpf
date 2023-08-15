---
title: eunomia-cc
catagories: ['ecc']
---

# eunomia-cc: compile and package ebpf programs

- A toolchain to simplify `writing` eBPF programs:
  - simplify building CO-RE[^1] `libbpf` eBPF applications: [write eBPF kernel code only](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/documents/introduction.md#simplify-building-co-re-libbpf-ebpf-applications) and automatically exposing your data with `perf event` or `ring buffer` from kernel.
  - [Automatically sample the data](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/documents/introduction.md#automatically-sample-the-data-and-print-hists-in-userspace) from hash maps and print `hists` in userspace.
  - [Automatically generate](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/documents/introduction.md#automatically-generate-and-config-command-line-arguments) and config `command line arguments` for eBPF programs.
  - You can writing the kernel part in both `BCC` and `libbpf` styles.
- Build eBPF programs with `Wasm`[^2]: see [`Wasm-bpf`](https://github.com/eunomia-bpf/wasm-bpf) project
  - Runtime, libraries and toolchains to [write eBPF with Wasm](https://github.com/eunomia-bpf/wasm-bpf) in C/C++, Rust, Go...covering the use cases from `tracing`, `networking`, `security`.
