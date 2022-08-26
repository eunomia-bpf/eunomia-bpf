## Kprobe

`kprobe` is an example of dealing with kernel-space entry and exit (return)
probes, `kprobe` and `kretprobe` in libbpf lingo. It attaches `kprobe` and
`kretprobe` BPF programs to the `do_unlinkat()` function and logs the PID,
filename, and return result, respectively, using `bpf_printk()` macro.

```shell
$ sudo ./kprobe
libbpf: loading object 'kprobe_bpf' from buffer
...
Successfully started!
...........
```

The `kprobe` demo output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```

## Run

(just replace the path as yours)

Compile:

```console
docker run -it -v /home/yunwei/coding/eunomia-bpf/bpftools/examples/kprobe-link:/src yunwei37/ebpm
```

Run:

```console
sudo ecli/build/bin/Release/ecli run bpftools/examples/kprobe-link/package.json
```