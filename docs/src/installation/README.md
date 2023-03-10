# Install

- Install the `ecli` tool for running eBPF program from the cloud:

    ```console
    $ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
    $ ./ecli -h
    Usage: ecli [--help] [--version] [--json] [--no-cache] url-and-args
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

  see [build](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/documents/build.md) for building details.
