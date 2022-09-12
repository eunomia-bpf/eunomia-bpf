# vfsstat

Detect key calls to the Virtual File System (VFS) interface

## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnlat.bpf.c

## Run

(just replace the path as yours)

Compile:

```shell
docker run -it -v /userpath/eunomia-bpf/bpftools/examples/vfsstat:/src yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run bpftools/examples/vfsstat/package.json
```

TODO: support union in C