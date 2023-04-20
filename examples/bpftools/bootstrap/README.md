---
layout: post
title: bootstrap
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, examples, tracepoint, ringbuf]
summary: an example of a simple (but realistic) BPF application tracks process starts (`exec()` family of syscalls, to be precise) and exits
---


`bootstrap` is an example of a simple (but realistic) BPF application. It
tracks process starts (`exec()` family of syscalls, to be precise) and exits
and emits data about filename, PID and parent PID, as well as exit status and
duration of the process life. With `-d <min-duration-ms>` you can specify
minimum duration of the process to log. In such mode process start
(technically, `exec()`) events are not output (see example output below).

`bootstrap` was created in the similar spirit as
[libbpf-tools: bootstrap](https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.bpf.c) from
BCC package, but is designed to be more stand-alone and with simpler Makefile
to simplify adoption to user's particular needs. It demonstrates the use of
typical BPF features:
  - cooperating BPF programs (tracepoint handlers for process `exec` and `exit`
    events, in this particular case);
  - BPF map for maintaining the state;
  - BPF ring buffer for sending data to user-space;
  - global variables for application behavior parameterization.
  - it utilizes BPF CO-RE and vmlinux.h to read extra process information from
    kernel's `struct task_struct`.

`bootstrap` is intended to be the starting point for your own BPF application,
with things like BPF CO-RE and vmlinux.h, consuming BPF ring buffer data,
command line arguments parsing, graceful Ctrl-C handling, etc. all taken care
of for you, which are crucial but mundane tasks that are no fun, but necessary
to be able to do anything useful. Just copy/paste and do simple renaming to get
yourself started.

Here's an example output in minimum process duration mode:

```console
$ sudo ecli run examples/bpftools/bootstrap/package.json
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    FILENAME  EXIT_EVENT  
20:18:47  30428  2915    0          0            sh      /bin/sh   0
20:18:47  30429  30428   0          0            which   /usr/bin/which 0
20:18:47  30429  30428   0          4552141      which             1
20:18:47  30428  2915    0          8430578      sh                1
20:18:47  30430  2915    0          0            sh      /bin/sh   0
20:18:47  30431  30430   0          0            ps      /usr/bin/ps 0
20:18:47  30431  30430   0          46361291     ps                1
20:18:47  30430  2915    0          54470349     sh                1
20:18:47  30432  2915    0          0            sh      /bin/sh   0
```

## System requirements:

- Linux kernel > 5.5
- Eunomia's [ecli](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/ecli) installed


## Run

- Compile:

  ```shell
  # for x86_64 and aarch64
  docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
  ```

  or

  ```shell
  ecc bootstrap.bpf.c bootstrap.h
  ```

- Run and help:

```console
$ sudo ./ecli run eunomia-bpf/examples/bpftools/bootstrap/package.json -h
Usage: bootstrap_bpf [--help] [--version] [--verbose] [--min_duration_ns VAR]

A simple eBPF program

Optional arguments:
  -h, --help            shows help message and exits 
  -v, --version         prints version information and exits 
  --verbose             prints libbpf debug information 
  --min_duration_ns     set value of long long unsigned int variable min_duration_ns 

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.
```
