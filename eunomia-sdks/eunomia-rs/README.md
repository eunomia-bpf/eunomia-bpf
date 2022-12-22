# A rust binding for eunomia-bpf

eunomia-bpf: https://github.com/eunomia-bpf/eunomia-bpf


## Our target: Run <abbr title="Compile Once - Run Everywhere">CO-RE</abbr> eBPF function as a service!

- Run `CO-RE` eBPF code without provisioning or managing infrastructure
- simply requests with a json and run `any` pre-compiled ebpf code on `any` kernel version
- very small and simple! Only a binary about `3MB`
- as fast as `100ms` to load and run a ebpf program
- `Distributed` and `decentralized`, No compile helper server

In general, we develop an approach to compile, transmit, and run most libbpf CO-RE objects with some user space config meta data to help us load and operator the eBPF byte code.

So, the only thing you need to do is focus on writing a single eBPF program in the kernel. We have a compiler here: [eunomia-cc](../eunomia-cc)


## Build

You will nedd to build the [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) as a library first, then you can use it in your program.

```sh
cd bpf-loader
make install
```
