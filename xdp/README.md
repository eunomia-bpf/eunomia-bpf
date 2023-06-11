---
layout: post
title: xdp
date: 2023-05-19 15:54
category: bpftools
author: ch3chohch3
tags: [bpftools, tc, example]
summary: a minimal example of a BPF application use xdp
---


`xdp` (short for eXpress Data Path) is an example of handling ingress network packets.
It attaches the `xdp_pass` BPF program to the `lo` network interface and print the size of the packets that coming into the `lo` interface to `trace_pipe`.

```console
$ sudo ecli run ./package.json
INFO [faerie::elf] strtab: 0x36c symtab 0x3a8 relocs 0x3f0 sh_offset 0x3f0
INFO [bpf_loader_lib::skeleton::poller] Running ebpf program...
```

You can find out the output by:

```
$ sudo cat /sys/kernel/tracing/trace_pipe
            node-1939    [000] d.s11  1601.190413: bpf_trace_printk: packet size is 177
            node-1939    [000] d.s11  1601.190479: bpf_trace_printk: packet size is 66
     ksoftirqd/1-19      [001] d.s.1  1601.237507: bpf_trace_printk: packet size is 66
            node-1939    [000] d.s11  1601.275860: bpf_trace_printk: packet size is 344
```

## Compile and Run

Compile:

```console
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

or compile with `ecc`:

```console
$ ecc xdp.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Run:

```console
sudo ecli run ./package.json
```