---
layout: post
title: tcpstates
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall]
summary: Trace TCP connection states.
---


# tcpstates

Trace TCP connection states.

## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnlat.bpf.c

## Run

Compile:

```shell
git clone https://github.com/eunomia-bpf/eunomia-bpf.git
docker run -it -v `pwd`/eunomia-bpf/examples/bpftools/tcpstates:/src yunwei37/ebpm
```

Run:

```shell
sudo ./ecli run eunomia-bpf/examples/bpftools/tcpstates/package.json
```
