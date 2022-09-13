# eunomia-exporter

An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: [eunomia-exporter](eunomia-exporter)

This is a single binary exporter, you don't need to install `BCC/LLVM` when you use it. The only thing you will need to run the exporter on another machine is the config file and pre-compiled eBPF code.

This component was written by rust,Please install `rust` before build.

```shell
$ curl -sSf https://static.rust-lang.org/rustup.sh | sh
```

## build
### Notice:You must compile `eunomia-bpf` before build `eunomia-exporter`. Details in https://github.com/eunomia-bpf/eunomia-bpf/blob/master/documents/build.md (documents/build.md)
You can compile the rust code from project root:

```shell
$ cargo build --release
```

After the compilation is complete, a folder named `target` can be found in the current directory.
```shell
$ cd target 
$ cd release
$ ls
```
You can see a binary called eunomia-exporter.
Change the binary file permission code, or you can't run it.
```shell
$ chmod 777 ./eunomia-exporter
$ ./eunomia-exporter -h
```

## example

This is an adapted version of opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c), you can check our source code here: [bpftools/examples/opensnoop](bpftools/examples/opensnoop)

You can compile the [opensnoop](bpftools/examples/opensnoop) like this:

```sh
$ cd bpftools/examples/opensnoop
$ docker run -it -v /userpath/eunomia-bpf/bpftools/examples/opensnoop:/src yunwei37/ebpm:latest
```
`userpath` needs to be replaced with your own path.

After compile the eBPF code, you can define a config file like this:

```yml
programs:
- name: opensnoop
  metrics:
    counters:
    - name: eunomia_file_open_counter
      description: test
      labels:
      - name: pid
      - name: comm
      - name: filename
        from: fname
  compiled_ebpf_filename: package.json
```

use the path to `package.json` as compiled_ebpf_filename in the config file. You can find the example at [config.yaml](bpftools/examples/opensnoop/config.yaml).

Then, you can start the exporter:

```console
$ cd /userpath/eunomia-bpf/bpftools/examples/opensnoop
$ cp /userpath/eunomia-bpf/eunomia-exporter/target/release/eunomia-exporter eunomia-exporter
$ sudo ./eunomia-exporter 

Running ebpf program opensnoop takes 46 ms
Listening on http://127.0.0.1:8526
running and waiting for the ebpf events from perf event...
Receiving request at path /metrics
```
`userpath` needs to be replaced with your own path.
 
 Different from the bcc ebpf_exporter, the only thing you need to run on the deployment machine is the `config file` and `package.json`. There is no need to install `LLVM/CLang` for BCC.

The result is:

![img](../documents/opensnoop_prometheus.png)

## manage eBPF tracing program via API

start an eBPF exporter via web API:

```sh
curl -X POST http://127.0.0.1:8526/start -H "Content-Type: application/json" -d @eunomia-exporter/examples/opensnoop/opensnoop_package.json
```

list all running eBPF programs:

```sh
curl http://127.0.0.1:8526/list
```

stop an eBPF program:

```sh
curl -X POST http://127.0.0.1:8526/stop -H "Content-Type: application/json" -d '{"id": 1}'
```

## benchmark

Take opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c) as an example. starting with BCC, you will need about 0.8s to start the exporter and attach to the probe. With out implement, you only need about `50-70ms` which is significantly faster.

```console
$ ps -aux | grep eunomia
root      171562  0.0  0.0  15176  4576 pts/6    S+   01:08   0:00 sudo ./eunomia-exporter
root      171605  0.1  0.0 350540  7740 pts/6    Sl+  01:08   0:00 ./eunomia-exporter
```

The memory usage and CPU usage is also low.

## Supported scenarios

Currently the only supported way of getting data out of the kernel is via maps (we call them tables in configuration).
