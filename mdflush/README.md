---
layout: post
title: mdflush
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, fentry]
summary: The mdflush tool traces flushes at the md driver level, and prints details including the time of the flush.
---



## origin

origin from:

<https://github.com/iovisor/bcc/blob/master/libbpf-tools/mdflush.bpf.c>

## Compile and Run

Compile:

```shell
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

or compile with `ecc`:

```console
$ ecc mdflush.bpf.c mdflush.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Run:

```console
$ sudo ecli run examples/bpftools/mdflush/package.json
TIME     PID     COMM    DISK
03:13:49 16770  sync     md0
03:14:08 16864  sync     md0
03:14:49 496    kworker/1:0H md0
03:14:49 488    xfsaild/md0  md0
03:14:54 488    xfsaild/md0  md0
03:15:00 488    xfsaild/md0  md0
```

## details in bcc

Demonstrations of mdflush, the Linux eBPF/bcc version.


The mdflush tool traces flushes at the md driver level, and prints details
including the time of the flush:

```console
# ./mdflush
Tracing md flush requests... Hit Ctrl-C to end.
TIME     PID    COMM             DEVICE
03:13:49 16770  sync             md0
03:14:08 16864  sync             md0
03:14:49 496    kworker/1:0H     md0
03:14:49 488    xfsaild/md0      md0
03:14:54 488    xfsaild/md0      md0
03:15:00 488    xfsaild/md0      md0
03:15:02 85     kswapd0          md0
03:15:02 488    xfsaild/md0      md0
03:15:05 488    xfsaild/md0      md0
03:15:08 488    xfsaild/md0      md0
03:15:10 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:11 488    xfsaild/md0      md0
03:15:12 488    xfsaild/md0      md0
03:15:13 488    xfsaild/md0      md0
03:15:15 488    xfsaild/md0      md0
03:15:19 496    kworker/1:0H     md0
03:15:49 496    kworker/1:0H     md0
03:15:55 18840  sync             md0
03:16:49 496    kworker/1:0H     md0
03:17:19 496    kworker/1:0H     md0
03:20:19 496    kworker/1:0H     md0
03:21:19 496    kworker/1:0H     md0
03:21:49 496    kworker/1:0H     md0
03:25:19 496    kworker/1:0H     md0
[...]
```
This can be useful for correlation with latency outliers or spikes in disk
latency, as measured using another tool (eg, system monitoring). If spikes in
disk latency often coincide with md flush events, then it would make flushing
a target for tuning.

Note that the flush events are likely to originate from higher in the I/O
stack, such as from file systems. This traces md processing them, and the
timestamp corresponds with when md began to issue the flush to disks.