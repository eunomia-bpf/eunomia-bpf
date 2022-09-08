# eunomia-exporter

An prometheus and OpenTelemetry exporter for custom eBPF metrics, written in async rust: [eunomia-exporter](eunomia-exporter)

#### example

This is an adapted version of opensnoop from [bcc/libbpf-tools](https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c), you can check our source code here: [bpftools/examples/opensnoop](bpftools/examples/opensnoop)

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
  compiled_ebpf_filename: bpftools/examples/opensnoop/package.json
```

use the 