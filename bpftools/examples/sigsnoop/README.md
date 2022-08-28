# sigsnoop

This traces signals generated system wide.

## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/sigsnoop.bpf.c

## Run

(just replace the path as yours)

Compile:

```shell
docker run -it -v /home/yunwei/coding/eunomia-bpf/bpftools/examples/sigsnoop:/src yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run bpftools/examples/sigsnoop/package.json
```