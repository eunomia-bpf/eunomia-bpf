# LSM demo

BPF LSM program (on socket_connect hook) that prevents any connection towards 1.1.1.1 to happen

## run

```console
docker run -it -v /home/yunwei/coding/eunomia-bpf/bpftools/examples/lsm-connect:/src yunwei37/ebpm:latest
```

Run:

```console
sudo ecli/build/bin/Release/ecli run bpftools/examples/lsm-connect/package.json
```

## reference

https://github.com/leodido/demo-cloud-native-ebpf-day