# md flush

Trace md flush events.

## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/mdflush.bpf.c

## Run

(just replace the path as yours)

Compile:

```shell
docker run -it -v /home/yunwei/coding/eunomia-bpf/bpftools/examples/mdflush:/src yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run bpftools/examples/mdflush/package.json
```
