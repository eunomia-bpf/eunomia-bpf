# eunomia-bpf: eBPF as a service

## Our target: Run <abbr title="Compile Once - Run Everywhere">CO-RE</abbr> eBPF function as a service!

- Run `CO-RE` eBPF code without provisioning or managing infrastructure
- simply requests with a json and run `any` pre-compiled ebpf code on `any` kernel version
- very small and simple! Only a binary about `3MB`
- as fast as `100ms` to load and run a ebpf program
- `Distributed` and `decentralized`, No compile helper server

## Our function

we have these parts:

### An eunomia-bpf library

A wrapper of main functions of libbpf, some helper functions for user development.

- provide the ability to load ebpf code to the kernel and run it.
- Use some additional data to help load and config the eBPF bytecode.
- multiple language bindings

see [eunomia-bpf](eunomia-bpf) folder for details.

### A cli tool

An simple and small pre-compiled binary, use eunomia-bpf library.

- simply pre-compiled ebpf data with a url or path:

    ```console
    $ sudo ./ecli run https://gitee.com/yunwei37/eunomia-bpf/raw/master/bpftools/examples/package.json
    $ sudo ./ecli run https://github.com/eunomia-bpf/eunomia-bpf/raw/master/bpftools/examples/package.json
    $ sudo ./ecli run bpftools/examples/package.json
    ```

- The cli tool can also run as a simple server to recive requests:

    ```console
    sudo ./ecli server
    ```
    we also provide a simple client for you to try. see [doc/ecli-usage.md](doc/ecli-usage.md) for more usages.

### A compile toolchain for you to generate pre compiled ebpf data

The toolchain can be used as a docker to generate pre-compiled ebpf data in one command:

see https://github.com/eunomia-bpf/ebpm-bootstrap for details.

you can also simply use it as a template in github, just push to it and github action can help you compile ebpf!

### An ebpf package manager: ebpm

see https://github.com/eunomia-bpf/ebpm for details.

## Road-map

- [X] refactor the code from project `Eunomia` and provide quick examples
- [ ] use lua for ebpf package load config
- [ ] add more possibilities from `libbpf`
- [ ] provide python, go and others sdk
- [ ] add support of `etcd` and enhance server
- [ ] fix ci and docs, multi proto supports

## License

This work is dual-licensed under BSD 2-clause license and GNU LGPL v2.1 license.
You can choose between one of them if you use this work.

`SPDX-License-Identifier: BSD-2-Clause OR LGPL-2.1`