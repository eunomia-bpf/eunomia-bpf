# a simple demo for eunomia-bpf

## build

```bash
mkdir build && cd build
cmake ..
make
```

## run

```console
$ build/demo
usage: build/demo <json config file>

$ sudo build/demo ../bpftools/opensnoop/package.json
{"ts":0,"pid":357,"uid":0,"ret":32,"flags":524288,"comm":"systemd-journal","fname":"/proc/148920/comm"}
{"ts":0,"pid":357,"uid":0,"ret":32,"flags":524288,"comm":"systemd-journal","fname":"/proc/148920/cmdline"}
{"ts":0,"pid":357,"uid":0,"ret":32,"flags":524288,"comm":"systemd-journal","fname":"/proc/148920/status"}
```