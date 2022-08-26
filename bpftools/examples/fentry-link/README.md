## Fentry

`fentry` is an example that uses fentry and fexit BPF programs for tracing. It
attaches `fentry` and `fexit` traces to `do_unlinkat()` which is called when a
file is deleted and logs the return value, PID, and filename to the
trace pipe.

Important differences, compared to kprobes, are improved performance and
usability. In this example, better usability is shown with the ability to
directly dereference pointer arguments, like in normal C, instead of using
various read helpers. The big distinction between **fexit** and **kretprobe**
programs is that fexit one has access to both input arguments and returned
result, while kretprobe can only access the result.

fentry and fexit programs are available starting from 5.5 kernels.

```shell
$ sudo ./fentry
libbpf: loading object 'fentry_bpf' from buffer
...
Successfully started!
..........
```

The `fentry` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```console
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file, ret = 0
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file2
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file2, ret = 0
```

## Run

(just replace the path as yours)

Compile:

```console
docker run -it -v /home/yunwei/coding/eunomia-bpf/bpftools/examples/fentry-link:/src yunwei37/ebpm
```

Run:

```console
sudo ecli/build/bin/Release/ecli run bpftools/examples/fentry-link/package.json
```