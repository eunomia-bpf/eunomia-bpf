# ecli

a simple cli interface for eunomia-bpf library, which you can use it to start any eBPF program from a url in a command.

## Install and Run

To install, just download and use the `binary`:

```bash
$ # download the release from https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli
$ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ecli
```

see [eunomia-bpf](../eunomia-bpf) folder for details. With the library, we have provide [a simple cli](https://github.com/eunomia-bpf/eunomia-bpf/releases/), you can simply run pre-compiled ebpf data with a url or path, on most eBPF supported kernel versions:

```bash
$ sudo ./ecli run https://eunomia-bpf.github.io/ebpm-template/package.json # simply run a pre-compiled ebpf code from a url
```

And you can compile and run the program, the only thing you need to do is write the [libbpf kernel C code](examples/bpftools/bootstrap/bootstrap.bpf.c):

```bash
$ docker run -it -v /path/to/repo/examples/bpftools/bootstrap:/src yunwei37/ebpm:latest
$ sudo ./ecli run examples/bpftools/bootstrap/package.json              # run the compiled ebpf code
```

The cli tool can also run as a simple server to receive requests, or as a client to send requests to another server. see [doc/ecli-usage.md](https://eunomia-bpf.github.io/ecli/index.html) for more usages.

For more examples, see [../examples/bpftools](examples/bpftools) directory.
