# examples of eunomia-bpf

- `bpftools`: some simple tools like in BCC
- `tests`: tests scripts of building `ecli` and `compiler`
- `simple-runner`: a simple runner to show how to use `eunomia-bpf` library in your project to dynamically load eBPF code from a `JSON`

## bpftools examples show usage of eunomia-bpf

## minimal example

`minimal` is just that – a minimal practical BPF application example. 

See [README.md](bpftools/minimal/README.md) for more details.

only kernel eBPF code is need when writing a minimal eBPF program. You can compile it and start it with `ecli` or the simple runner above

## bootstrap example

`bootstrap` is an example of a simple (but realistic) BPF application. It
tracks process starts (`exec()` family of syscalls, to be precise) and exits
and emits data about filename, PID and parent PID, as well as exit status and
duration of the process life.

see [README.md](bpftools/bootstrap/README.md) for more details.

only kernel eBPF code is need when writing a minimal eBPF program. 
You can compile it and start it with `ecli` or the simple runner above

## opensnoop exmaple

opensnoop traces the open() syscall system-wide, and prints various details. 
This example is ship with a `config.yaml`, you can use it for eunomia-exporter:

```yaml
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

see [README.md](bpftools/opensnoop/README.md) for more details.

see the [eunomia-exporter/README.md](../eunomia-exporter/README.md) for how to use the exporter.

## sigsnoop example

example with WASM module. This traces signals generated system wide.

see [README.md](bpftools/sigsnoop/README.md) for more details.

Generate WASM skel:

> The skel is generated and commit, so you don't need to generate it again.
> skel includes:
> - eunomia-include: include headers for WASM
> - app.c: the WASM app. all library is header only.

```shell
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest gen-wasm-skel
```

Build WASM module

```shell
# for x86_64 and aarch64
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest build-wasm
```

Run:

```console
$ sudo ./ecli run app.wasm -h
Usage: sigsnoop [-h] [-x] [-k] [-n] [-p PID] [-s SIGNAL]
Trace standard and real-time signals.


    -h, --help  show this help message and exit
    -x, --failed  failed signals only
    -k, --killed  kill only
    -p, --pid=<int>  target pid
    -s, --signal=<int>  target signal

$ sudo ./ecli run app.wasm                                                                       
running and waiting for the ebpf events from perf event...
{"pid":185539,"tpid":185538,"sig":17,"ret":0,"comm":"cat","sig_name":"SIGCHLD"}
{"pid":185540,"tpid":185538,"sig":17,"ret":0,"comm":"grep","sig_name":"SIGCHLD"}

$ sudo ./ecli run app.wasm -p 1641
running and waiting for the ebpf events from perf event...
{"pid":1641,"tpid":2368,"sig":23,"ret":0,"comm":"YDLive","sig_name":"SIGURG"}
{"pid":1641,"tpid":2368,"sig":23,"ret":0,"comm":"YDLive","sig_name":"SIGURG"}
```

