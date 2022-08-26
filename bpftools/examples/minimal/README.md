## Minimal

`minimal` is just that – a minimal practical BPF application example. It
doesn't use or require BPF CO-RE, so should run on quite old kernels. It
installs a tracepoint handler which is triggered once every second. It uses
`bpf_printk()` BPF helper to communicate with the world. To see it's output,
read `/sys/kernel/debug/tracing/trace_pipe` file as a root:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: BPF triggered from PID 3840345.
           <...>-3840345 [010] d... 3220702.101265: bpf_trace_printk: BPF triggered from PID 3840345.
```

`minimal` is great as a bare-bones experimental playground to quickly try out
new ideas or BPF features.

## Run

(just replace the path as yours)

Compile:

```console
docker run -it -v /home/yunwei/coding/eunomia-bpf/bpftools/examples/minimal:/src yunwei37/ebpm
```

Run:

```console
sudo ecli/build/bin/Release/ecli run bpftools/examples/minimal/package.json
```