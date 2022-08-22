# eunomia-bpf: eBPF as a service

## Our target: Run CO-RE eBPF function as a service!

- Run `CO-RE` eBPF code without provisioning or managing infrastructure
- simply requests with a json and run `every` pre-compiled ebpf code
- very small and simple! Only a binary bout `4MB`
- as fast as `100ms` to start a ebpf program
- `Distributed` and `decentralized`, No compile helper server

## Our function

we have two parts:

### eunomia-bpf library

A wrapper of main functions of libbpf, some helper functions for user development.

- provide the ability to load ebpf code to the kernel and run it.
- Use some additional data to help load and config the eBPF bytecode.
- multiple language bindings

### A cli tool and a server

An simple and small pre-compiled binary, use eunomia-bpf library.

- simply pre-compiled ebpf data with a url or path:

    ```console
    sudo ecli run http://example.com/package.json
    sudo ecli run bpftools/opensnoop/package.json
    ```

- run as a server to recive requests:

    ```console
    sudo ecli server
    ```

    and you can start any ebpf program with a simple request!

## Road-map

TODO

## License

This work is dual-licensed under BSD 2-clause license and GNU LGPL v2.1 license.
You can choose between one of them if you use this work.

`SPDX-License-Identifier: BSD-2-Clause OR LGPL-2.1`