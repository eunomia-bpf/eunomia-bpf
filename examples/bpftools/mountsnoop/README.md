## mountsnoop


## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/mountsnoop.bpf.c


## Run

(just replace the path as yours)

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run examples/bpftools/mountsnoop/package.json
```

TODO: support enum types in C
