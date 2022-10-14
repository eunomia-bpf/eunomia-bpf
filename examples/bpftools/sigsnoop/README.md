---
layout: post
title: sigsnoop
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall]
summary: Trace signal syscalls.
---


## origin

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/sigsnoop.bpf.c

## Compile and Run

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

## details in bcc

Demonstrations of sigsnoop.


This traces signals generated system wide. For example:
```console
# ./sigsnoop -n
TIME     PID     COMM             SIG       TPID    RESULT
19:56:14 3204808 a.out            SIGSEGV   3204808 0
19:56:14 3204808 a.out            SIGPIPE   3204808 0
19:56:14 3204808 a.out            SIGCHLD   3204722 0
```
The first line showed that a.out (a test program) deliver a SIGSEGV signal.
The result, 0, means success.

The second and third lines showed that a.out also deliver SIGPIPE/SIGCHLD
signals successively.

USAGE message:
```console
# ./sigsnoop -h
Usage: sigsnoop [OPTION...]
Trace standard and real-time signals.

USAGE: sigsnoop [-h] [-x] [-k] [-n] [-p PID] [-s SIGNAL]

EXAMPLES:
    sigsnoop             # trace signals system-wide
    sigsnoop -k          # trace signals issued by kill syscall only
    sigsnoop -x          # trace failed signals only
    sigsnoop -p 1216     # only trace PID 1216
    sigsnoop -s 9        # only trace signal 9

  -k, --kill                 Trace signals issued by kill syscall only.
  -n, --name                 Output signal name instead of signal number.
  -p, --pid=PID              Process ID to trace
  -s, --signal=SIGNAL        Signal to trace.
  -x, --failed               Trace failed signals only.
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```
Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

Report bugs to https://github.com/iovisor/bcc/tree/master/libbpf-tools.