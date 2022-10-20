# Build on Android

在Android上构建时，需要先Installing Debian on Android in Termux 

1. install termux

https://github.com/termux/termux-app/releases/tag/v0.118.0

2.install proot-distro

select debian distro

```
pkg install proot-distro
proot-distro install debian
proot-distro login debian
```

3.install packages

remember `proot-distro login debian` first

```
apk update
apt install clang cmake libelf1 libelf-dev zlib1g-dev
```

之后的步骤和在ARM上build上相同

# Build on  ARM




 步骤和在Android上类似

1.确认内核BTF选项已经打开

```
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
```

2.确认当前内核BTF信息可用

若/sys/kernel/btf/vmlinux存在，则可通过bpftool生成vmlinux.h

```
 apt install linux-tools-(uname -r)-generic
 apt install linux-tools-generic
 bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

若/sys/kernel/btf/vmlinux不存在，通过[btfhub](https://github.com/aquasecurity/btfhub)添加外源BTF信息或生成当前内核的定制化BTF信息

（1）添加外源BTF信息

参考 [BTFgen tool to create smaller BTF files](https://github.com/aquasecurity/btfhub/blob/main/docs/generating-tailored-btfs.md)

```
$ git clone git@github.com:aquasecurity/btfhub.git
$ git clone git@github.com:aquasecurity/btfhub-archive.git
$ cd btfhub ; ls
//将克隆的归档文件放入 btfhub 目录
$ rsync -avz ../btfhub-archive/ --exclude=.git* --exclude=README.md ./archive/
//生成定制的 eBPF 对象的 BTF 文件:
$ ./tools/btfgen.sh -a AARCH64 -o $HOME/tracee.bpf.core.o
```

检查定制的新生成的 BTF 文件及其尺寸

```
$ find custom-archive | grep ubuntu | tail -10
$ls -lah custom-archive/ubuntu/20.04/x86_64/5.8.0-1041-azure.btf
```

（2）生成当前内核的定制化BTF信息

导入 BTFhub-Archive 存储库的未压缩的完整 BTF 文件

```
$ sudo ./example-static
$ sudo ./example-c-static
$ sudo EXAMPLE_BTF_FILE=5.8.0-63-generic.btf ./example-static
$ sudo EXAMPLE_BTF_FILE=5.8.0-63-generic.btf ./example-c-static
```



3.同步 eunomia-bpf 到本地

```
git clone https://github.com/eunomia-bpf/eunomia-bpf.git
cd eunomia-bpf
git submodule update --init --recursive
```

4.配置环境变量

```
export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
```

5.安装依赖

```
apk update
apt install clang cmake libelf1 libelf-dev zlib1g-dev
```

6.修改ewasm/CMakeLists.txt` 中的 `WAMR_BUILD_TARGET

change `set (WAMR_BUILD_TARGET "X86_64")` to `set (WAMR_BUILD_TARGET "AARCH64")`

7.编译

```
make eunomia-bpf
make ecli
```

8.检查输出

```
root@localhost:~/eunomia-bpf# file ecli/build/bin/Release/ecli
ecli/build/bin/Release/ecli: ELF executable, 64-bit LSB arm64, dynamic (/lib/ld-linux-aarch64.so.1), BuildID=f278cb3bce8ff3934201d2112a4e741061c5978a, not stripped
```

