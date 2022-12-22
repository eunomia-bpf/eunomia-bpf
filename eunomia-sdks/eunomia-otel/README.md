# eunomia-exporter

An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: [eunomia-exporter](eunomia-exporter)

This is a single binary exporter, you don't need to install `BCC/LLVM` when you use it. The only thing you will need to run the exporter on another machine is the config file and pre-compiled eBPF code.

## example

This is an adapted version of opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c), you can check our source code here: [examples/bpftools/opensnoop](examples/bpftools/opensnoop)

You can just download the pre-compiled [opensnoop package.json](https://eunomia-bpf.github.io/eunomia-bpf/opensnoop/package.json).

Or you can compile the [opensnoop](examples/bpftools/opensnoop) like this:

```sh
$ cd examples/bpftools/opensnoop
$ docker run -it -v /userpath/eunomia-bpf/examples/bpftools/opensnoop:/src yunwei37/ebpm:latest
```
`userpath` needs to be replaced with your own repo path.

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

use the path to `package.json` as compiled_ebpf_filename in the config file. You can find the example at [config.yaml](examples/bpftools/opensnoop/config.yaml).

Then, you can start the exporter:

```console
$ ls
config.yaml  eunomia-exporter package.json
$ sudo ./eunomia-exporter

Running ebpf program opensnoop takes 46 ms
Listening on http://127.0.0.1:8526
running and waiting for the ebpf events from perf event...
Receiving request at path /metrics
```

Different from the bcc ebpf_exporter, the only thing you need to run on the deployment machine is the `config file` and `package.json`. There is no need to install `LLVM/CLang` for BCC.

The result is:

![img](../documents/images/opensnoop_prometheus.png)

## manage eBPF tracing program via API

start an eBPF exporter via web API:

```console
$ curl -X POST http://127.0.0.1:8526/start -H "Content-Type: application/json" -d @examples/opensnoop/curl_post_example.json

{"id":1}
```

see [curl_post_example.json](eunomia-exporter/examples/opensnoop/curl_post_example.json) for the example of the request body.

list all running eBPF programs:

```console
$ curl http://127.0.0.1:8526/list

[{"id":0,"name":"bootstrap"},{"id":1,"name":"opensnoop"}]
```

stop an eBPF program:

```sh
$ curl -X POST http://127.0.0.1:8526/stop -H "Content-Type: application/json" -d '{"id": 1}'
```

## build

Notice: You must compile `bpf-loader` before build `eunomia-exporter`. Details in [build.md](../documents/build.md)

This component was written by rust,Please install `rust` before build.

```shell
$ curl https://sh.rustup.rs -sSf | sh
```

You can compile the rust code in this folder:

```console
$ cargo build --release
$ target/release/eunomia-exporter -h
eunomia-exporter 0.1.0

USAGE:
    eunomia-exporter [OPTIONS]

OPTIONS:
    -c, --config <CONFIG>    Sets a custom config file [default: config.yaml]
    -h, --help               Print help information
    -V, --version            Print version information
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
