![logo](https://eunomia.dev/assets/logo.png)

# eunomia-bpf: simplify and enhance eBPF with CO-RE[^1] and WebAssembly[^2]

[![Actions Status](https://github.com/eunomia-bpf/eunomia-bpf/workflows/Ubuntu/badge.svg)](https://github.com/eunomia-bpf/eunomia-bpf/actions)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/eunomia-bpf/eunomia-bpf)](https://github.com/eunomia-bpf/eunomia-bpf/releases)
[![codecov](https://codecov.io/gh/eunomia-bpf/eunomia-bpf/branch/master/graph/badge.svg?token=YTR1M16I70)](https://codecov.io/gh/eunomia-bpf/eunomia-bpf)
[![DeepSource](https://deepsource.io/gh/eunomia-bpf/eunomia-bpf.svg/?label=active+issues&show_trend=true&token=rcSI3J1-gpwLIgZWtKZC-N6C)](https://deepsource.io/gh/eunomia-bpf/eunomia-bpf/?ref=repository-badge)
[![CodeFactor](https://www.codefactor.io/repository/github/eunomia-bpf/eunomia-bpf/badge)](https://www.codefactor.io/repository/github/eunomia-bpf/eunomia-bpf)

**A compiler and runtime framework to help you build and distribute eBPF program easier.**

## Introduction

`eunomia-bpf` is a dynamic loading library/runtime and a compile toolchain framework, aim at helping you build and distribute eBPF programs easier.

Project documentation is maintained in [eunomia.dev](https://eunomia.dev/eunomia-bpf/) and its source now lives in [eunomia-bpf/eunomia.dev](https://github.com/eunomia-bpf/eunomia.dev).

With eunnomia-bpf, you can:

- A library to simplify `writing` eBPF programs:
  - simplify building CO-RE[^1] `libbpf` eBPF applications: [write eBPF kernel code only](https://eunomia.dev/eunomia-bpf/introduction/) and automatically exposing your data with `perf event` or `ring buffer` from kernel.
  - [Automatically sample the data](https://eunomia.dev/eunomia-bpf/introduction/) from hash maps and print `hists` in userspace.
  - [Automatically generate](https://eunomia.dev/eunomia-bpf/introduction/) and config `command line arguments` for eBPF programs.
  - You can writing the kernel part in both `BCC` and `libbpf` styles.
- Build eBPF programs with `Wasm`[^2]: see [`Wasm-bpf`](https://github.com/eunomia-bpf/wasm-bpf) project
  - Runtime, libraries and toolchains to [write eBPF with Wasm](https://github.com/eunomia-bpf/wasm-bpf) in C/C++, Rust, Go...covering the use cases from `tracing`, `networking`, `security`.
- simplify `distributing` eBPF programs:
  - A [tool](ecli/) for push, pull and run pre-compiled eBPF programs as `OCI` images in Wasm module
  - Run eBPF programs from `cloud` or `URL` within [`1` line of bash](https://eunomia.dev/eunomia-bpf/introduction/) without recompiling, kernel version and architecture independent.
  - [Dynamically load](bpf-loader-rs) eBPF programs with `JSON` config file or `Wasm` module.

For more information, see the [eunomia-bpf documentation](https://eunomia.dev/eunomia-bpf/).

[^1]: CO-RE: [Compile Once – Run Everywhere](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)
[^2]: WebAssembly or Wasm: <https://webassembly.org/>

## Getting Started

- Github Template：[eunomia-bpf/ebpm-template](https://github.com/eunomia-bpf/ebpm-template)
- example bpf programs: [examples/bpftools](examples/bpftools/)
- tutorial: [eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)

### run as cli tool or server

You can get pre-compiled eBPF programs running from an OCI registry to the kernel in `1` line of bash:

```bash
# download the latest release from GitHub Releases
$ wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli -O ecli && chmod +x ./ecli
$ sudo ./ecli run ghcr.io/eunomia-bpf/execve:latest # run a pre-compiled ebpf tool from OCI registry
[79130] node -> /bin/sh -c which ps 
[79131] sh -> which ps 
[79132] node -> /bin/sh -c /usr/bin/ps -ax -o pid=,ppid=,pcpu=,pmem=,c 
[79133] sh -> /usr/bin/ps -ax -o pid=,ppid=,pcpu=,pmem=,command= 
[79134] node -> /bin/sh -c "/home/yunwei/.vscode-server/bin/2ccd690cbf 
[79135] sh -> /home/yunwei/.vscode-server/bin/2ccd690cbff 78132 79119 79120 79121 
[79136] cpuUsage.sh -> sed -n s/^cpu\s//p /proc/stat
```

You can also use a server to manage and dynamically install eBPF programs.

Start the server:

```console
$ sudo ./ecli-server
[2023-08-08 02:02:03.864009 +08:00] INFO [server/src/main.rs:95] Serving at 127.0.0.1:8527
```

Use the ecli to control the remote server and manage multiple eBPF programs:

```console
$ ./ecli client start sigsnoop.json # start the program
1
$ ./ecli client log 1 # get the log of the program
TIME     PID    TPID   SIG    RET    COMM   
02:05:58  79725 78132  17     0      bash
02:05:59  77325 77297  0      0      node
02:05:59  77297 8042   0      0      node
02:05:59  77297 8042   0      0      node
02:05:59  79727 79726  17     0      which
02:05:59  79726 8084   17     0      sh
02:05:59  79731 79730  17     0      which
```

For more information, see [the ecli server documentation](https://eunomia.dev/eunomia-bpf/ecli/server/).

## Install the project

- Install the `ecli` tool for running eBPF program from the cloud:

    ```console
    $ wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli -O ecli && chmod +x ./ecli
    $ ./ecli -h
    ecli subcommands, including run, push, pull

    Usage: ecli [COMMAND_LINE]... [COMMAND]

    Commands:
      run     run ebpf program
      client  Client operations
      push    Operations about pushing image to registry
      pull    Operations about pulling image from registry
      help    Print this message or the help of the given subcommand(s)

    Arguments:
      [COMMAND_LINE]...  Not preferred. Only for compatibility to older versions. Command line to run. The executable could either be a local path or URL or `-` (read from stdin). The following arguments will be passed to the program

    Options:
      -h, --help  Print help
    ....
    ```

- Install the `ecc` compiler-toolchain for compiling eBPF kernel code to a `config` file or `Wasm` module(`clang`, `llvm`, and `libclang` should be installed for compiling):

    ```console
    $ wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
    $ ./ecc -h
    eunomia-bpf compiler
    Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]
    ....
    ```

  or use the docker image for compile:

    ```bash
    # for x86_64 and aarch64
    docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest # compile with docker. `pwd` should contains *.bpf.c files and *.h files.
    ```

- build the compiler, runtime library and tools:

  see [build](https://eunomia.dev/eunomia-bpf/setup/build) for building details.

## Examples

See [examples](examples) for details about simple eBPF tools and eunomia-bpf library usage.

See [github.com/eunomia-bpf/wasm-bpf/tree/main/examples](https://github.com/eunomia-bpf/wasm-bpf/tree/main/examples) for Wasm eBPF programs and examples.

We also have a prove of concept video: [Writing eBPF programs in Wasm](https://www.bilibili.com/video/BV1JN4y1A76k/).

## License

MIT LICENSE
