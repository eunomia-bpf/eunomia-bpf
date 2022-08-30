# tcpconnlat

Trace TCP connects and show connection latency.

## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnlat.bpf.c

## Run

(just replace the path as yours)

Compile:

```shell
docker run -it -v /home/yunwei/coding/eunomia-bpf/bpftools/examples/tcpconnlat:/src yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run bpftools/examples/tcpconnlat/package.json
```

TODO: support union in C