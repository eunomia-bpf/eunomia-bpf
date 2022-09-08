# eunomia-exporter

An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: [eunomia-exporter](eunomia-exporter)

This is a single binary exporter, you don't need to install `BCC/LLVM` when you use it. The only thing you will need to run the exporter on another machine is the config file and pre-compiled eBPF code.

## build

You can compile the rust code from project root:

```shell
$ make eunomia-exporter
```

for more details, see [documents/build.md](documents/build.md). You can get a pre-build binary from [release](https://github.com/eunomia-bpf/eunomia-bpf/releases/)

## example

This is an adapted version of opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c), you can check our source code here: [bpftools/examples/opensnoop](bpftools/examples/opensnoop)

You can compile the [opensnoop](bpftools/examples/opensnoop) like this:

```sh
$ cd bpftools/examples/opensnoop
$ docker run -it -v /path/to/repo/bpftools/examples/opensnoop:/src yunwei37/ebpm:latest
```

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
$ sudo ./eunomia-exporter

Running ebpf program opensnoop takes 46 ms
Listening on http://127.0.0.1:8526
running and waiting for the ebpf events from perf event...
Receiving request at path /metrics
```

Different from the bcc ebpf_exporter, the only thing you need to run on the deployment machine is the `config file` and `package.json`. There is no need to install `LLVM/CLang` for BCC.

The result is:

![img](../documents/opensnoop_prometheus.png)

## hot install eBPF tracing program

## benchmark

Take opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c) as an example. starting with BCC, you will need about 0.8s to start the exporter and attach to the probe. With out implement, you only need about `50-70ms` which is significantly faster.

```console
$ ps -aux | grep eunomia
root      171562  0.0  0.0  15176  4576 pts/6    S+   01:08   0:00 sudo ./eunomia-exporter
root      171605  0.1  0.0 350540  7740 pts/6    Sl+  01:08   0:00 ./eunomia-exporter
```

The memory usage and CPU usage is also low.