## opensnoop

opensnoop traces the open() syscall system-wide, and prints various details.

## result

origin from:

https://github.com/iovisor/bcc/blob/master/libbpf-tools/opensnoop.bpf.c

result:

```console
$ sudo ecli/build/bin/Release/ecli run bpftools/examples/opensnoop/package.json

running and waiting for the ebpf events from perf event...
time ts pid uid ret flags comm fname 
00:58:08 0 812 0 9 524288 vmtoolsd /etc/mtab 
00:58:08 0 812 0 11 0 vmtoolsd /proc/devices 
00:58:08 0 34351 0 24 524288 ecli /etc/localtime 
00:58:08 0 812 0 9 0 vmtoolsd /sys/class/block/sda5/../device/../../../class 
00:58:08 0 812 0 -2 0 vmtoolsd /sys/class/block/sda5/../device/../../../label 
00:58:08 0 812 0 9 0 vmtoolsd /sys/class/block/sda1/../device/../../../class 
00:58:08 0 812 0 -2 0 vmtoolsd /sys/class/block/sda1/../device/../../../label 
00:58:08 0 812 0 9 0 vmtoolsd /run/systemd/resolve/resolv.conf 
00:58:08 0 812 0 9 0 vmtoolsd /proc/net/route 
00:58:08 0 812 0 9 0 vmtoolsd /proc/net/ipv6_route 
```

## Run

(just replace the path as yours)

Compile:

```shell
docker run -it -v /home/yunwei/coding/eunomia-bpf/bpftools/examples/opensnoop:/src yunwei37/ebpm:latest
```

Run:

```shell
sudo ./ecli run bpftools/examples/opensnoop/package.json
```