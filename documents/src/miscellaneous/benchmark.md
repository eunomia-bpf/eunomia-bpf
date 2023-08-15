---
title: benchmark
catagories: ['misc']
---



# benchmark

Most of the time, bpf-loader work as a library to load eBPF program. It will not affect eBPF program after the program has been loaded and attached.

TODO: add more benchmark results

## benchmark for loading with exporter

Take opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c) as an example. starting with BCC, you will need about 0.8s to start the exporter and attach to the probe. With out implement, you only need about `50-70ms` which is significantly faster.

```console
$ ps -aux | grep eunomia
root      171562  0.0  0.0  15176  4576 pts/6    S+   01:08   0:00 sudo ./eunomia-exporter
root      171605  0.1  0.0 350540  7740 pts/6    Sl+  01:08   0:00 ./eunomia-exporter
```

The memory usage and CPU usage is also low. see [eunomia-exporter](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/eunomia-sdks/eunomia-otel) for more details.
