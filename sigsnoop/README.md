---
layout: post
title: sigsnoop
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall, kprobe, tracepoint]
summary: Trace signals generated system wide, from syscalls and others.
---

## origin bcc code

origin from:

<https://github.com/iovisor/bcc/blob/master/libbpf-tools/sigsnoop.bpf.c>

This example include a eBPF program and a WASM module in user space.

## compile and run eBPF+Wasm example

### Download ecc compiler and ecli runtime tool

- Install the `ecli` tool for running eBPF program:

    ```console
    $ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
    $ ./ecli -h
    Usage: ecli [--help] [--version] [--json] [--no-cache] url-and-args
    ....
    ```

- Install the `ecc` compiler-toolchain for compiling eBPF kernel code to a `config` file or `WASM` module(`clang`, `llvm`, and `libclang` should be installed for compiling), and install `struct-bindgen` for generating the export event header:

    ```console
    $ wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
    $ ./ecc -h
    eunomia-bpf compiler
    Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]
    ....
    $ wget https://github.com/eunomia-bpf/c-struct-bindgen/releases/download/v0.1.0/struct-bindgen && chmod +x ./struct-bindgen
    ```

- Install WASI:

    ```console
    wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-17/wasi-sdk-17.0-linux.tar.gz
    tar -zxf wasi-sdk-17.0-linux.tar.gz
    sudo mkdir -p /opt/wasi-sdk/ && sudo mv wasi-sdk-17.0/* /opt/wasi-sdk/
    ```

### compile

Compile eBPF program:

```console
$ ./ecc sigsnoop.bpf.c sigsnoop.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

A `package.json` file is generated, which contains the compiled eBPF program and the config file.

Generate WASM skel:

```shell
./ecc sigsnoop.bpf.c sigsnoop.h --wasm-header
./ecc sigsnoop.h --header-only
./struct-bindgen sigsnoop.h > sigsnoop.wasm.h
```

A `ewasm-skel.h` file is generated, which contains the WASM skel for eBPF, and A `sigsnoop.wasm.h` for accessing event passed from eBPF in Wasm.

Run build.sh to build WASM module:

```shell
./build.sh
```

### Run eBPF-Wasm program

```console
$ sudo ./ecli run sigsnoop.wasm -h
Usage: sigsnoop [-h] [-x] [-k] [-n] [-p PID] [-s SIGNAL]
Trace standard and real-time signals.


    -h, --help  show this help message and exit
    -x, --failed  failed signals only
    -k, --killed  kill only
    -p, --pid=<int>  target pid
    -s, --signal=<int>  target signal

$ sudo ./ecli run sigsnoop.wasm                                                                     
running and waiting for the ebpf events from perf event...
{"pid":185539,"tpid":185538,"sig":17,"ret":0,"comm":"cat","sig_name":"SIGCHLD"}
{"pid":185540,"tpid":185538,"sig":17,"ret":0,"comm":"grep","sig_name":"SIGCHLD"}

$ sudo ./ecli run sigsnoop.wasm -p 1641
running and waiting for the ebpf events from perf event...
{"pid":1641,"tpid":2368,"sig":23,"ret":0,"comm":"YDLive","sig_name":"SIGURG"}
{"pid":1641,"tpid":2368,"sig":23,"ret":0,"comm":"YDLive","sig_name":"SIGURG"}
```

## compile and run WASM example with docker

Generate WASM skel:

```shell
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest gen-wasm-skel
```

> The skel is generated and commit, so you don't need to generate it again.
> skel includes:
>
> - eunomia-include: include headers for WASM
> - app.c: the WASM app. all library is header only.

Build WASM module

```shell
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest build-wasm
```

or install the [WASI SDK](https://github.com/WebAssembly/wasi-sdk/releases/download), and use the build script:

```shell
./build.sh
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


## Compile and Run eBPF only

Compile:

```shell
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

Or compile with `ecc`:

```console
$ ecc sigsnoop.bpf.c sigsnoop.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
```

Run:

```console
$ sudo ./ecli examples/bpftools/sigsnoop/package.json
TIME     PID     TPID    SIG     RET     COMM    
20:43:44  21276  3054    0       0       cpptools-srv
20:43:44  22407  3054    0       0       cpptools-srv
20:43:44  20222  3054    0       0       cpptools-srv
20:43:44  8933   3054    0       0       cpptools-srv
20:43:44  2915   2803    0       0       node
20:43:44  2943   2803    0       0       node
20:43:44  31453  3054    0       0       cpptools-srv
$ sudo ./ecli examples/bpftools/sigsnoop/package.json  -h
Usage: sigsnoop_bpf [--help] [--version] [--verbose] [--filtered_pid VAR] [--target_signal VAR] [--failed_only]

A simple eBPF program

Optional arguments:
  -h, --help            shows help message and exits 
  -v, --version         prints version information and exits 
  --verbose             prints libbpf debug information 
  --filtered_pid        set value of pid_t variable filtered_pid 
  --target_signal       set value of int variable target_signal 
  --failed_only         set value of bool variable failed_only 

Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.
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

Report bugs to <https://github.com/iovisor/bcc/tree/master/libbpf-tools>.
