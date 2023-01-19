# a simple demo for ewasm

## build

```bash
mkdir build && cd build
cmake ..
make
```

## run

```console
$ build/ewasm_demo
usage: ./build/ewasm_demo [path of wasm file]  [-j path of json file]

$ sudo ./build/ewasm_demo ../../wasm-runtime/test/wasm-apps/opensnoop.wasm 
{"ts":0,"pid":153,"uid":0,"ret":5,"flags":32768,"comm":"init","fname":"/proc/net/tcp"}
{"ts":0,"pid":153,"uid":0,"ret":5,"flags":32768,"comm":"init","fname":"/proc/net/tcp6"}
{"ts":0,"pid":153,"uid":0,"ret":5,"flags":32768,"comm":"init","fname":"/proc/net/tcp"}
{"ts":0,"pid":153,"uid":0,"ret":5,"flags":32768,"comm":"init","fname":"/proc/net/tcp6"}

$ sudo ./build/ewasm_demo -j ../bpftools/minimal/package.json
Runing eBPF program...
# you can find the result in /sys/kernel/debug/tracing/trace_pipe
$ cat /sys/kernel/debug/tracing/trace_pipe
            node-6196    [007] d...1 49239.306373: bpf_trace_printk: my info: BPF triggered from PID 6196.

            sudo-22727   [003] d...1 49239.306391: bpf_trace_printk: my info: BPF triggered from PID 22727.

            init-6195    [000] d...1 49239.306413: bpf_trace_printk: my info: BPF triggered from PID 6195.
```