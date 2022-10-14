---
layout: post
title: bindsnoop
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, syscall, kprobe, perf_event]
summary: Trace bind syscalls.
---

# sigsnoop

Trace bind syscalls.

## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/bindsnoop.bpf.c

## Run

(just replace the path as yours)

Compile:

```shell
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run examples/bpftools/bindsnoop/package.json
```
