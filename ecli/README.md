# oci-compatible tooling for eunomia-bpf runner

## examples

pull an image from a registry

```bash
ecli pull https://ghcr.io/eunomia-bpf/sigsnoop:latest
```

push an image to a registry

```bash
ecli push https://ghcr.io/eunomia-bpf/sigsnoop:latest
ecli push https://yunwei37:[password]@ghcr.io/eunomia-bpf/sigsnoop:latest
```

Run the program:

```console
$ sudo ./ecli run examples/bpftools/bootstrap/package.json
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    FILENAME  EXIT_EVENT  
22:01:04  46310  2915    0          0            sh      /bin/sh   0
22:01:04  46311  46310   0          0            which   /usr/bin/which 0
22:01:04  46311  46310   0          2823776      which             1
22:01:04  46310  2915    0          6288891      sh                1
22:01:04  46312  2915    0          0            sh      /bin/sh   0
22:01:04  46313  46312   0          0            ps      /usr/bin/ps 0
```

## build

```bash
make
```