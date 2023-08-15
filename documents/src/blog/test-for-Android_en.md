# Running the ecli on Android 13
>
>Author: CH3CHOHCH3

# Abstract

This article mainly records the author's exploration process, results, and encountered issues when testing the support level of the high version Android Kernel for CO-RE technology based on libbpf in the Android Studio Emulator. The testing method used is to build a Debian environment in the Android Shell environment and attempt to build the eunomia-bpf toolchain and run its test cases based on this environment.

# Background

As of now (2023-04), Android has not provided good support for dynamic loading of eBPF programs. Whether it is the compiler distribution scheme represented by bcc or the CO-RE scheme based on btf and libbpf, they are largely dependent on the support of the Linux environment and cannot run well on the Android system [^WeiShu].

However, there have been some successful cases of trying eBPF on the Android platform. In addition to the scheme provided by Google, which modifies `Android.bp` to build and mount eBPF programs with the entire system [^Google], some people have proposed the idea of ​​building a Linux environment based on the Android kernel to run eBPF toolchains and have developed related tools.

Currently existing materials mostly rely on adeb/eadb to build Linux sandboxes based on the Android kernel and test bcc and bpftrace toolchains, but there is less testing work on the CO-RE scheme. There are more reference materials for using the bcc tool on Android, such as:

+ SeeFlowerX: <https://blog.seeflower.dev/category/eBPF/>
+ evilpan: <https://bbs.kanxue.com/thread-271043.htm>

The main idea is to use chroot to run a Debian image on the Android kernel and build the entire bcc toolchain in it, thus using eBPF tools. The principle is similar if you want to use bpftrace.

In fact, the high version of the Android kernel already supports the btf option, which means that the emerging CO-RE technology in the eBPF field should also be able to be applied to Linux systems based on the Android kernel. This article will test and run eunomia-bpf in the emulator environment based on this.

> [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) is an open-source project that combines libbpf and WebAssembly technologies, aiming to simplify the writing, compiling, and deployment of eBPF programs. This project can be regarded as a practical way of CO-RE, which relies on libbpf at its core. It is believed that the testing work of eunomia-bpf can provide reference for other CO-RE schemes.

# Testing Environment

+ Android Emulator (Android Studio Flamingo | 2022.2.1)
+ AVD: Pixel 6
+ Android Image: Tiramisu Android 13.0 x86_64 (5.15.41-android13-8-00055-g4f5025129fe8-ab8949913)

# Environment Setup [^SeeFlowerX]

1. Obtain `debianfs-amd64-full.tar.gz` from the releases page of the [eadb repository](https://github.com/tiann/eadb) as the rootfs of the Linux environment, and also get the `assets` directory of the project to build the environment.
2. Configure and start the Android Virtual Device in Android Studio's Device Manager.
3. Use the adb tool of the Android Studio SDK to push `debianfs-amd64-full.tar.gz` and the `assets` directory to the AVD:
   + `./adb push debianfs-amd64-full.tar.gz /data/local/tmp/deb.tar.gz`
   + `./adb push assets /data/local/tmp/assets`
4. Use adb to enter the Android shell environment and obtain root permissions:
   + `./adb shell`
   + `su`
5. Build and enter the Debian environment in the Android shell:
   + `mkdir -p /data/eadb`
   + `mv /data/local/tmp/assets/* /data/eadb`
   + `mv /data/local/tmp/deb.tar.gz /data/eadb/deb.tar.gz`+ `rm -r /data/local/tmp/assets`
   + `chmod +x /data/eadb/device-*`
   + `/data/eadb/device-unpack`
   + `/data/eadb/run /data/eadb/debian`

The Linux environment required for testing eBPF has been built. In addition, in the Android shell (before entering debian), you can use `zcat /proc/config.gz` with `grep` to view the kernel compilation options.
>Currently, the debian environment packaged by eadb has a low libc version and lacks many tool dependencies. Additionally, due to different kernel compilation options, some eBPF functionalities may not be available.
>
# Tool Building

Clone the eunomia-bpf repository to the local debian environment. For specific building process, please refer to the [build.md](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/documents/build.md) in the repository. In this test, I used the `ecc` compiler to generate `package.json`, and the build and usage methods of this tool can be found on the [repository page](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/compiler).
>During the building process, you may need to manually install tools such as `curl`, `pkg-config`, `libssl-dev`, etc.
>
# Test Results

## Successful Cases

### [bootstrap](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/bootstrap)

The running output is as follows:

```sh
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    FILENAME  EXIT_EVENT
09:09:19  10217  479     0          0            sh      /system/bin/sh 0
09:09:19  10217  479     0          0            ps      /system/bin/ps 0
09:09:19  10217  479     0          54352100     ps                1
09:09:21  10219  479     0          0            sh      /system/bin/sh 0
09:09:21  10219  479     0          0            ps      /system/bin/ps 0
09:09:21  10219  479     0          44260900     ps                1
```

### [tcpstates](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/tcpstates)

After monitoring starts, download the web page using `wget` in the Linux environment:

```sh
TIME     SADDR   DADDR   SKADDR  TS_US   DELTA_US  PID     OLDSTATE  NEWSTATE  FAMILY  SPORT   DPORT   TASK
09:07:46  0x4007000200005000000000000f02000a 0x5000000000000f02000a8bc53f77 18446635827774444352 3315344998 0 10115 7 2 2 0 80 wget
09:07:46  0x40020002d98e50003d99f8090f02000a 0xd98e50003d99f8090f02000a8bc53f77 18446635827774444352 3315465870 120872 0 2 1 2 55694 80 swapper/0
09:07:46  0x40010002d98e50003d99f8090f02000a 0xd98e50003d99f8090f02000a8bc53f77 18446635827774444352 3315668799 202929 10115 1 4 2 55694 80 wget".
```

format: Return only the translated content, not including the original text.09:07:46  0x40040002d98e50003d99f8090f02000a 0xd98e50003d99f8090f02000a8bc53f77 18446635827774444352 3315670037 1237 0 4 5 2 55694 80 swapper/0
09:07:46  0x40050002000050003d99f8090f02000a 0x50003d99f8090f02000a8bc53f77 18446635827774444352 3315670225 188 0 5 7 2 55694 80 swapper/0
09:07:47  0x400200020000bb01565811650f02000a 0xbb01565811650f02000a6aa0d9ac 18446635828348806592 3316433261 0 2546 2 7 2 49970 443 ChromiumNet
09:07:47  0x400200020000bb01db794a690f02000a 0xbb01db794a690f02000aea2afb8e 18446635827774427776 3316535591 0 1469 2 7 2 37386 443 ChromiumNet

Begin testing by opening the Chrome browser on the Android Studio simulation 
and visiting the Baidu webpage:

```sh
TIME     SADDR   DADDR   SKADDR  TS_US   DELTA_US  PID     OLDSTATE  NEWSTATE  FAMILY  SPORT   DPORT   TASK
07:46:58  0x400700020000bb01000000000f02000a 0xbb01000000000f02000aeb6f2270 18446631020066638144 192874641 0 3305 7 2 2 0 443 NetworkService
07:46:58  0x40020002d28abb01494b6ebe0f02000a 0xd28abb01494b6ebe0f02000aeb6f2270 18446631020066638144 192921938 47297 3305 2 1 2 53898 443 NetworkService
07:46:58  0x400700020000bb01000000000f02000a 0xbb01000000000f02000ae7e7e8b7 18446631020132433920 193111426 0 3305 7 2 2 0 443 NetworkService
07:46:58  0x40020002b4a0bb0179ff85e80f02000a 0xb4a0bb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193124670 13244 3305 2 1 2 46240 443 NetworkService
07:46:58  0x40010002b4a0bb0179ff85e80f02000a 0xb4a0bb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193185397 60727 3305 1 4 2 46240 443 NetworkService
07:46:58  0x40040002b4a0bb0179ff85e80f02000a 0xb4a0bb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193186122 724 3305 4 5 2 46240 443 NetworkService
07:46:58  0x400500020000bb0179ff85e80f02000a 0xbb0179ff85e80f02000ae7e7e8b7 18446631020132433920 193186244 122 3305 5 7 2 46240 443 NetworkService
07:46:59  0x40010002d01ebb01d0c52f5c0f02000a 0xd01ebb01d0c52f5c0f02000a51449c27 18446631020103553856 194110884 0 5130 1 8 2 53278 443 ThreadPoolForeg".07:46:59  0x400800020000bb01d0c52f5c0f02000a 0xbb01d0c52f5c0f02000a51449c27 18446631020103553856 194121000 10116 3305 8 7 2 53278 443 NetworkService
07:46:59  0x400700020000bb01000000000f02000a 0xbb01000000000f02000aeb6f2270 18446631020099513920 194603677 0 3305 7 2 2 0 443 NetworkService
07:46:59  0x40020002d28ebb0182dd92990f02000a 0xd28ebb0182dd92990f02000aeb6f2270 18446631020099513920 194649313 45635 12 2 1 2 53902 443 ksoftirqd/0
07:47:00  0x400700020000bb01000000000f02000a 0xbb01000000000f02000a26f6e878 18446631020132433920 195193350 0 3305 7 2 2 0 443 NetworkService
07:47:00  0x40020002ba32bb01e0e09e3a0f02000a 0xba32bb01e0e09e3a0f02000a26f6e878 18446631020132433920 195206992 13642 0 2 1 2 47666 443 swapper/0
07:47:00  0x400700020000bb01000000000f02000a 0xbb01000000000f02000ae7e7e8b7 18446631020132448128 195233125 0 3305 7 2 2 0 443 NetworkService
07:47:00  0x40020002b4a8bb0136cac8dd0f02000a 0xb4a8bb0136cac8dd0f02000ae7e7e8b7 18446631020132448128 195246569 13444 3305 2 1 2 46248 443 NetworkService
07:47:00  0xf02000affff00000000000000000000 0x1aca06cffff00000000000000000000 18446631019225912320 195383897 0 947 7 2 10 0 80 Thread-11
07:47:00  0x40010002b4a8bb0136cac8dd0f02000a 0xb4a8bb0136cac8dd0f02000ae7e7e8b7 18446631020132448128 195421584 175014 3305 1 4 2 46248 443 NetworkService
07:47:00  0x40040002b4a8bb0136cac8dd0f02000a 0xb4a8bb0136cac8dd0f02000ae7e7e8b7 18446631020132448128 195422361 777 3305 4 5 2 46248 443 NetworkService
07:47:00  0x400500020000bb0136cac8dd0f02000a 0xbb0136cac8dd0f02000ae7e7e8b7 18446631020132448128 195422450 88 3305 5 7 2 46248 443 NetworkService
07:47:01  0x400700020000bb01000000000f02000a 0xbb01000000000f02000aea2afb8e 18446631020099528128 196321556 0 1315 7 2 2 0 443 ChromiumNet

## Failed Cases

### [fentry-link](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/fentry-link)

Builds successfully, but encounters an error when running:

```sh
libbpf: prog 'do_unlinkat': failed to attach: Device or resource busy
libbpf: prog 'do_unlinkat': failed to auto-attach: -16
failed to attach skeleton".
```

Please note that this is a translation of the Markdown text provided.Error: BpfError("load and attach ebpf program failed")
```

### [opensnoop](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/opensnoop)

Successfully built, but encountered an error when running:

```sh
libbpf: failed to determine tracepoint 'syscalls/sys_enter_open' perf event ID: No such file or directory
libbpf: prog 'tracepoint__syscalls__sys_enter_open': failed to create tracepoint 'syscalls/sys_enter_open' perf event: No such file or directory
libbpf: prog 'tracepoint__syscalls__sys_enter_open': failed to auto-attach: -2
failed to attach skeleton
Error: BpfError("load and attach ebpf program failed")
```

After investigation, it was found that the `CONFIG_FTRACE_SYSCALLS` option was not enabled in the kernel, which caused the tracepoint for syscalls to be unavailable.

### [runqlat](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/runqlat)

Encountered an error during the build process:

```sh
Compiling bpf object...
$ clang -g -O2 -target bpf -Wno-unknown-attributes -D__TARGET_ARCH_x86 -idirafter /usr/local/include -idirafter /usr/lib/llvm-11/lib/clang/11.0.1/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include  -I/tmp/eunomia.9fwyJN/include -I/tmp/eunomia.9fwyJN/include/vmlinux/x86  -I/root/eunomia-bpf/examples/bpftools/runqlat -c examples/bpftools/runqlat/runqlat.bpf.temp.c -o examples/bpftools/runqlat/runqlat.bpf.o
 In file included from examples/bpftools/runqlat/runqlat.bpf.temp.c:10:
/root/eunomia-bpf/examples/bpftools/runqlat/core_fixes.bpf.h:76:9: error: use of unknown builtin '__builtin_preserve_type_info' [-Wimplicit-function-declaration]
    if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x))
        ^
/tmp/eunomia.9fwyJN/include/bpf/bpf_core_read.h:185:2: note: expanded from macro 'bpf_core_type_exists'
        __builtin_preserve_type_info(*(typeof(type) *)0, BPF_TYPE_EXISTS)
        ^
/root/eunomia-bpf/examples/bpftools/runqlat/core_fixes.bpf.h:76:9: note: did you mean '__builtin_preserve_field_info'?
/tmp/eunomia.9fwyJN/include/bpf/bpf_core_read.h:185:2: note: expanded from macro 'bpf_core_type_exists'
        __builtin_preserve_type_info(*(typeof(type) *)0, BPF_TYPE_EXISTS)".
```^
/root/eunomia-bpf/examples/bpftools/runqlat/core_fixes.bpf.h:27:9: note: '__builtin_preserve_field_info' declared here
    if (bpf_core_field_exists(t->__state))
        ^
/tmp/eunomia.9fwyJN/include/bpf/bpf_core_read.h:132:2: note: expanded from macro 'bpf_core_field_exists'
        __builtin_preserve_field_info(___bpf_field_ref(field), BPF_FIELD_EXISTS)
        ^
In file included from examples/bpftools/runqlat/runqlat.bpf.temp.c:10:
/root/eunomia-bpf/examples/bpftools/runqlat/core_fixes.bpf.h:76:9: warning: indirection of non-volatile null pointer will be deleted, not trap [-Wnull-dereference]
    if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x))
        ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/tmp/eunomia.9fwyJN/include/bpf/bpf_core_read.h:185:31: note: expanded from macro 'bpf_core_type_exists'
        __builtin_preserve_type_info(*(typeof(type) *)0, BPF_TYPE_EXISTS)
                                     ^~~~~~~~~~~~~~~~~~
/root/eunomia-bpf/examples/bpftools/runqlat/core_fixes.bpf.h:76:9: note: consider using __builtin_trap() or qualifying pointer with 'volatile'
/tmp/eunomia.9fwyJN/include/bpf/bpf_core_read.h:185:31: note: expanded from macro 'bpf_core_type_exists'
        __builtin_preserve_type_info(*(typeof(type) *)0, BPF_TYPE_EXISTS)
                                     ^
1 warning and 1 error generated.

thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: No such file or directory (os error 2)', src/compile_bpf.rs:171:37
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

The specific cause of the error currently needs further investigation.

# Summary

In the Android shell, it can be observed that the `CONFIG_DEBUG_INFO_BTF` kernel compilation option is enabled by default. On this basis, the examples provided by the eunomia-bpf project already have some successful cases, such as monitoring the execution of the `exec` function family and the tcp connection state.

For projects that cannot run, the reasons are mainly as follows:

1. The kernel compilation options do not support the relevant eBPF features;
2. The Linux environment packaged by eadb is relatively weak and lacks necessary dependencies;

Currently, using eBPF tools in the Android system still requires building a complete Linux runtime environment. However, the Android kernel itself has comprehensive support for eBPF. The test this time proves that higher versions of the Android kernel support BTF debugging information and the execution of eBPF programs dependent on CO-RE.Instructions: Translate the following Chinese text to English 
while maintaining the original formatting: "Android system eBPF tool development requires the addition of official new features. At present, it seems that using eBPF tools directly through Android apps requires a lot of work. Additionally, since eBPF tools require root permissions, ordinary Android users will face many difficulties.

# References

[^Google]: <https://source.android.google.cn/docs/core/architecture/kernel/bpf>
[^WeiShu]: <https://mp.weixin.qq.com/s/mul4n5D3nXThjxuHV7GpMA>
[^SeeFlowerX]: <https://blog.seeflower.dev/archives/138/>".
format: Return only the translated content, not including the original text.