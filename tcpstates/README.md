---
layout: post
title: tcpstates
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall]
summary: Tcpstates prints TCP state change information, including the duration in each state as milliseconds
---


## origin

origin from:

<https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpstates.bpf.c>

## Compile and Run

Compile:

```shell
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

Or compile with `ecc`:

```console
$ ecc tcpstates.bpf.c tcpstates.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Run:

```console
$ sudo ./ecli run examples/bpftools/tcpstates/package.json -h
Usage: tcpstates_bpf [--help] [--version] [--verbose] [--filter_by_sport] [--filter_by_dport] [--target_family VAR]

A simple eBPF program

Optional arguments:
  -h, --help            shows help message and exits 
  -v, --version         prints version information and exits 
  --verbose             prints libbpf debug information 
  --filter_by_sport     set value of bool variable filter_by_sport 
  --filter_by_dport     set value of bool variable filter_by_dport 
  --target_family       set value of short variable target_family 

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.
```

## details in bcc

Demonstrations of tcpstates, the Linux BPF/bcc version.

tcpstates prints TCP state change information, including the duration in each
state as milliseconds. For example, a single TCP session:

```console
# tcpstates
SKADDR           C-PID C-COMM     LADDR           LPORT RADDR           RPORT OLDSTATE    -> NEWSTATE    MS
ffff9fd7e8192000 22384 curl       100.66.100.185  0     52.33.159.26    80    CLOSE       -> SYN_SENT    0.000
ffff9fd7e8192000 0     swapper/5  100.66.100.185  63446 52.33.159.26    80    SYN_SENT    -> ESTABLISHED 1.373
ffff9fd7e8192000 22384 curl       100.66.100.185  63446 52.33.159.26    80    ESTABLISHED -> FIN_WAIT1   176.042
ffff9fd7e8192000 0     swapper/5  100.66.100.185  63446 52.33.159.26    80    FIN_WAIT1   -> FIN_WAIT2   0.536
ffff9fd7e8192000 0     swapper/5  100.66.100.185  63446 52.33.159.26    80    FIN_WAIT2   -> CLOSE       0.006
^C
```

This showed that the most time was spent in the ESTABLISHED state (which then
transitioned to FIN_WAIT1), which was 176.042 milliseconds.

The first column is the socked address, as the output may include lines from
different sessions interleaved. The next two columns show the current on-CPU
process ID and command name: these may show the process that owns the TCP
session, depending on whether the state change executes synchronously in
process context. If that's not the case, they may show kernel details.
