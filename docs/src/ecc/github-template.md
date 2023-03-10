# Github Action 模板

ebpm-template：使用 Github Action 进行远程编译，本地一键运行；

请参考：https://github.com/eunomia-bpf/ebpm-template

# A template for eunomia-bpf programs

This is a template for eunomia-bpf eBPF programs. You can use t as a template, compile it online with `Github Actions` or offline.

### Compile and run the eBPF code as simple as possible!

Download the pre-compiled `ecli` binary from here: [eunomia-bpf/eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf/releases)

To install, just download and use the `ecli` binary from here: [eunomia-bpf/eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf/releases):

```console
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ecli
```

## use this repo as a github action to compile online

1. use this repo as a github template: see [creating-a-repository-from-a-template](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template)
2. modify the `bootstrap.bpf.c`, commit it and wait for the workflow to stop
3. Run the `ecli` with remote url:

```console
$ sudo ./ecli run https://eunomia-bpf.github.io/ebpm-template/package.json
```

## quick start

just write some code in the `bootstrap.bpf.c`, after that, simply run this:

```shell
$ docker run -it -v /path/to/repo:/src yunwei37/ebpm:latest # use absolute path
```

you will get a `package.json` in your root dir. Just run:

```shell
$ sudo ./ecli run package.json
```

The ebpf compiled code can run on different kernel versions(CO-RE). You can just copied the json to another machine.
see: [github.com/eunomia-bpf/eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) for the runtime, and [eunomia-bpf/eunomia-cc](https://github.com/eunomia-bpf/eunomia-cc) for our compiler tool chains.

## The code here

This is an example of ebpf code, we copied the bootstrap.bpf.c from [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap/tree/master/examples/c), without any modification. You can read their `README` for details: https://github.com/libbpf/libbpf-bootstrap

## more examples

for more examples, please see: [eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools)
