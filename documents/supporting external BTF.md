# Build on  ARM

1.确认内核BTF选项已经打开

```
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
```

如果内核选项未开启，就需要重新编译内核

2. 确认当前内核BTF信息是否可用，如不可用需添加外源BTF信息

若/sys/kernel/btf/vmlinux存在，则BTF可用，可通过bpftool生成vmlinux.h

```sh
 apt install linux-tools-(uname -r)-generic
 apt install linux-tools-generic
 bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

若/sys/kernel/btf/vmlinux不存在，则BTF不可用，可通过[btfhub](https://github.com/aquasecurity/btfhub)添加外源BTF信息或生成当前内核的定制化BTF信息

（1）添加外源BTF信息

参考 [BTFgen tool to create smaller BTF files](https://github.com/aquasecurity/btfhub/blob/main/docs/generating-tailored-btfs.md)

```sh
$ git clone git@github.com:aquasecurity/btfhub.git
$ git clone git@github.com:aquasecurity/btfhub-archive.git
$ cd btfhub ; ls
//将克隆的归档文件放入 btfhub 目录
$ rsync -avz ../btfhub-archive/ --exclude=.git* --exclude=README.md ./archive/
```

整个btfhub-archive目录相当庞大，可以单独下载某个BTF归档文件放入btfhub 目录

```
$ rsync -avz ../5.11.0-1027-azure.btf.tar.xz --exclude=.git* --exclude=README.md ./archive/
sending incremental file list

sent 77 bytes  received 12 bytes  178.00 bytes/sec
total size is 144,419  speedup is 1,622.69
```

之后就可以根据某个对应的eBPF 对象生成定制的BTF 文件

```
//生成定制的 eBPF 对象的 BTF 文件:
$ ./tools/btfgen.sh -a AARCH64 -o $HOME/****.bpf.core.o
```

检查定制的新生成的 BTF 文件及其尺寸

```sh
$ find custom-archive | grep ubuntu | tail -10
$ls -lah custom-archive/ubuntu/20.04/x86_64/5.8.0-1041-azure.btf
```

（2）生成当前内核的定制化BTF信息

```sh
$ sudo ./example-static
$ sudo ./example-c-static
$ sudo EXAMPLE_BTF_FILE=5.8.0-63-generic.btf ./example-static
$ sudo EXAMPLE_BTF_FILE=5.8.0-63-generic.btf ./example-c-static
```
