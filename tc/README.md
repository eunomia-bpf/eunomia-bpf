---
layout: post
title: tc
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, tc, example]
summary: a minimal example of a BPF application use tc
---


`tc` (short for Traffic Control) is an example of handling ingress network traffics.
It creates a qdisc on the `lo` interface and attaches the `tc_ingress` BPF program to it.
It reports the metadata of the IP packets that coming into the `lo` interface.

```shell
$ sudo ecli run ./package.json
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF program.
......
```

The `tc` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            node-1254811 [007] ..s1 8737831.671074: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674334: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674349: 0: Got IP packet: tot_len: 72, ttl: 64
            node-1254811 [007] ..s1 8737831.674550: 0: Got IP packet: tot_len: 71, ttl: 64
```

## Compile and Run

 

Compile:

```console
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

or compile with `ecc`:

```console
$ ecc tc.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Run:

```console
sudo ecli run ./package.json
```