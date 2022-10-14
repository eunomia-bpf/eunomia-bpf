---
layout: post
title: bootstrap
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, examples, tracepoint, ringbuf]
summary: an example of a simple (but realistic) BPF application
---

## Bootstrap

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
$ sudo ./bootstrap -d 50
running and waiting for the ebpf events...
01:21:48 167307 166025 0 0 sh /bin/sh 0
01:21:48 167308 167307 0 0 which /usr/bin/which 0
01:21:48 167308 167307 0 3515432 which  1
01:21:48 167307 166025 0 8797379 sh  1
01:21:49 167309 166025 0 0 sh /bin/sh 0
01:21:49 167310 167309 0 0 ps /usr/bin/ps 0
01:21:49 167310 167309 0 83298343 ps  1
01:21:49 167309 166025 0 88504290 sh  1
01:21:49 167311 166025 0 0 sh /bin/sh 0
...
```

## System requirements:

- Linux kernel > 5.5
- Eunomia's [ecli](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/ecli) installed



## Run

Compile:

```shell
git clone https://github.com/eunomia-bpf/eunomia-bpf.git
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run eunomia-bpf/examples/bpftools/bootstrap/package.json
```
