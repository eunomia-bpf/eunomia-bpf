## example

This is an adapted version of opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c), you can check our source code here: [examples/bpftools/opensnoop](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/opensnoop)

You can just download the pre-compiled [opensnoop package.json](https://eunomia-bpf.github.io/eunomia-bpf/opensnoop/package.json).

Or you can compile the [opensnoop](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/opensnoop) like this:

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

use the path to `package.json` as compiled_ebpf_filename in the config file. You can find the example at [config.yaml](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/examples/bpftools/opensnoop/config.yaml).

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

![prometheus](https://oss.openanolis.cn/sig/stxfomyiiwdwkdrqwlnn)

## manage eBPF tracing program via API

start an eBPF exporter via web API:

```console
$ curl -X POST http://127.0.0.1:8526/start -H "Content-Type: application/json" -d @examples/opensnoop/curl_post_example.json

{"id":1}
```

see [curl_post_example.json](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/eunomia-exporter/examples/opensnoop/curl_post_example.json) for the example of the request body.

list all running eBPF programs:

```console
$ curl http://127.0.0.1:8526/list

[{"id":0,"name":"bootstrap"},{"id":1,"name":"opensnoop"}]
```

stop an eBPF program:

```sh
$ curl -X POST http://127.0.0.1:8526/stop -H "Content-Type: application/json" -d '{"id": 1}'
```

documents:

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
