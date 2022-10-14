---
layout: post
title: lsm-connect
date: 2022-10-10 16:18
category: bpftools
author: yunwei37
tags: [bpftools, examples, lsm, no-output]
summary: BPF LSM program (on socket_connect hook) that prevents any connection towards 1.1.1.1 to happen
---


# LSM demo

BPF LSM program (on socket_connect hook) that prevents any connection towards 1.1.1.1 to happen

## run

```console
docker run -it -v `pwd`/:/src/ yunwei37/ebpm:latest
```

Run:

```console
sudo ecli/build/bin/Release/ecli run examples/bpftools/lsm-connect/package.json
```

## reference

https://github.com/leodido/demo-cloud-native-ebpf-day