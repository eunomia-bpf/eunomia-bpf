---
layout: post
title: sigsnoop
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall]
summary: Trace signal syscalls.
---


# sigsnoop

This traces signals generated system wide.

## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/sigsnoop.bpf.c

## Run

(just replace the path as yours)

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```console
$ sudo ./ecli run package.json

running and waiting for the ebpf events from perf event...
time pid tpid sig ret comm 
00:24:14 169126 168102 0 0 cpptools-srv 
00:24:14 166416 1804 0 0 node 
00:24:14 168438 166416 0 0 node 
00:24:14 163282 1804 0 0 node 
00:24:14 104109 102346 0 0 cpptools-srv
```



## WASM example

Generate WASM skel:

> The skel is generated and commit, so you don't need to generate it again.
> skel includes:
> - eunomia-include: include headers for WASM
> - app.c: the WASM app. all library is header only.

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest gen-wasm-skel
```

Build WASM module

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest build-wasm
```

Run:

```console
$ sudo ./ecli run app.wasm -h
Usage: sigsnoop [-h] [-x] [-k] [-n] [-p PID] [-s SIGNAL]
Trace standard and real-time signals.


    -h, --help  show this help message and exit
    -x, --failed  failed signals only
    -k, --killed  kill only
    -p, --pid=<int>  target pid
    -s, --signal=<int>  target signal

$ sudo ./ecli run app.wasm                                                                       
running and waiting for the ebpf events from perf event...
{"pid":185539,"tpid":185538,"sig":17,"ret":0,"comm":"cat","sig_name":"SIGCHLD"}
{"pid":185540,"tpid":185538,"sig":17,"ret":0,"comm":"grep","sig_name":"SIGCHLD"}

$ sudo ./ecli run app.wasm -p 1641
running and waiting for the ebpf events from perf event...
{"pid":1641,"tpid":2368,"sig":23,"ret":0,"comm":"YDLive","sig_name":"SIGURG"}
{"pid":1641,"tpid":2368,"sig":23,"ret":0,"comm":"YDLive","sig_name":"SIGURG"}
```