# eunomia-exporter

An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: eunomia-exporter

This is a single binary exporter, you don't need to install `BCC/LLVM` when you use it. The only thing you will need to run the exporter on another machine is the config file and pre-compiled eBPF code.

## Supported scenarios

Currently the only supported way of getting data out of the kernel is via maps (we call them tables in configuration).
