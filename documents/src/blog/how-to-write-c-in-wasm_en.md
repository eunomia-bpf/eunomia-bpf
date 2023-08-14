# Writing eBPF Programs in C/C++ and libbpf in WebAssembly

> Authors: Yu Tong, Zheng Yusheng

eBPF (extended Berkeley Packet Filter) is a high-performance kernel virtual machine that runs in the kernel space and is used to collect system and network information. With the continuous development of computer technology, eBPF has become increasingly powerful and is used to build various efficient online diagnostic and tracing systems, as well as secure networks and service meshes.

WebAssembly (Wasm) was initially developed for browser security sandbox purposes. As of now, WebAssembly has evolved into a high-performance, cross-platform, and multi-language software sandbox environment for cloud-native software components. The lightweight nature of Wasm containers makes them suitable for running as the next-generation serverless platform runtime or for efficient execution in resource-constrained scenarios such as edge computing.

Now, with the help of the Wasm-bpf compilation toolchain and runtime, we can use Wasm to write eBPF programs as cross-platform modules, while using C/C++ or Rust to write Wasm programs. By using eBPF programs in WebAssembly, we not only enable Wasm applications to benefit from the high performance and access to system interfaces of eBPF, but also allow eBPF programs to leverage the sandboxing, flexibility, cross-platform nature, and dynamic loading of Wasm. Additionally, we can conveniently and quickly distribute and manage eBPF programs using Wasm OCI images. Combining these two technologies will provide a completely new development experience for the eBPF and Wasm ecosystems!

## Writing, Dynamically Loading, and Distributing eBPF Programs in Wasm with the Wasm-bpf Toolchain

Wasm-bpf is a new open-source project: [https://github.com/eunomia-bpf/wasm-bpf](https://github.com/eunomia-bpf/wasm-bpf). It defines an abstraction for the eBPF-related system interfaces and provides a corresponding development toolchain, library, and a general Wasm + eBPF runtime instance. It can provide a similar development experience to libbpf-bootstrap, automatically generating skeleton header files and data structure definitions for unordered communication between Wasm and eBPF. With this toolchain, you can easily build your own Wasm-eBPF runtime in any language on any platform. For more details, please refer to our previous blog post: [Wasm-bpf: Bridging WebAssembly and eBPF Kernel Programmability](https://mp.weixin.qq.com/s/2InV7z1wcWic5ifmAXSiew).

With Wasm, we can build eBPF applications using multiple languages and manage and distribute them in a unified and lightweight manner. As an example, our sample application bootstrap.wasm is only ~90K in size, making it easy to distribute over the network and dynamically deploy, load, and run on another machine in less than 100ms, while retaining the isolation characteristics of lightweight containers. The runtime does not require kernel headers, LLVM, clang, or any resource-consuming heavy compilation work.

This article will discuss writing and compiling eBPF programs in C/C++ and converting them into Wasm modules. A specific example of writing and compiling eBPF programs in Rust and converting them into Wasm modules will be described in the next article.

We provide several sample programs in the repository, each corresponding to different scenarios such as observability, networking, and security.

## Writing eBPF Programs in C/C++ and Compiling into Wasm

libbpf is a C/C++ user space loading and control library for eBPF and has become the de facto API standard for eBPF user space. libbpf also supports the CO-RE (Compile Once - Run Everywhere) solution, which allows precompiled BPF code to work on different kernel versions without the need to recompile for each specific kernel. We aim to maintain compatibility and minimize migration costs to Wasm (if necessary) by keeping the user space API and behavior consistent with libbpf.

libbpf-bootstrap provides templates for generating libbpf-based BPF programs, making it easy for developers to generate custom BPF programs. In general, outside the Wasm sandbox, using the libbpf-bootstrap scaffolding, you can quickly and easily build BPF applications using C/C++.

The compilation, building, and running of eBPF programs (regardless of the programming language) usually involve the following steps:

- Write the code for the kernel space eBPF program, generally using C/C++ or Rust.
- Compile the eBPF program using the clang compiler or related toolchains (including BTF information to achieve cross-kernel version portability).
- In the user space development program, write the corresponding logic for loading, controlling, mounting, and processing data.
- During runtime, load the eBPF program into the kernel from the user space and execute it.

### bootstrap

`bootstrap` is a simple (but practical) example of a BPF application. It tracks the startup (specifically, the `exec()` series of system calls) and exit of processes, and sends data about the file name, PID, and parent PID, as well as the exit status and duration of the process. With `-d <min-duration-ms>`, you can specify the minimum duration of the processes to be recorded.

`bootstrap` is created based on the similar idea of [libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools) in the BCC package, but it is designed to be more independent and has a simpler Makefile to simplify user's specific needs. It demonstrates typical BPF features, including cooperation with multiple BPF program segments, maintaining state using BPF maps, sending data to userspace using BPF ring buffer, and parameterizing application behavior using global variables.

Here is an example output of running `bootstrap` by compiling it with Wasm:

```console
$ sudo sudo ./wasm-bpf bootstrap.wasm -h
BPF bootstrap demo application.

It traces process start and exits and shows associated
information (filename, process duration, PID and PPID, etc).

USAGE: ./bootstrap [-d <min-duration-ms>] -v
$ sudo ./wasm-bpf bootstrap.wasm
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
18:57:58 EXEC  sed              74911   74910   /usr/bin/sed
18:57:58 EXIT  sed              74911   74910   [0] (2ms)
18:57:58 EXIT  cat              74912   74910   [0] (0ms)
18:57:58 EXEC  cat              74913   74910   /usr/bin/cat
18:57:59 EXIT  cat              74913   74910   [0] (0ms)
18:57:59 EXEC  cat              74914   74910   /usr/bin/cat
18:57:59 EXIT  cat              74914   74910   [0] (0ms)
18:57:59 EXEC  cat              74915   74910   /usr/bin/cat
18:57:59 EXIT  cat              74915   74910   [0] (1ms)
18:57:59 EXEC  sleep            74916   74910   /usr/bin/sleep
```

We can provide a development experience similar to libbpf-bootstrap. Just run `make` to build the wasm binary:

```console
git clone https://github.com/eunomia-bpf/wasm-bpf --recursive
cd examples/bootstrap
make
```

### Writing eBPF programs in kernel space

To build a complete eBPF program, you need to first write the BPF code in kernel space. This is typically done using the C language and compiled using clang:

```c
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");".const volatile unsigned long long min_duration_ns = 0;
const volatile int *name_ptr;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    unsigned fname_off;
    struct event *e;
    pid_t pid;
    u64 ts;
....
```

Due to space constraints, the full code is not shown here. The way to write kernel code is exactly the same as other libbpf-based programs. Generally, it includes some global variables, eBPF functions declared with `SEC` for mounting points, and map objects used to store state or communicate between user space and kernel space (we are also doing other work in progress: [bcc to libbpf converter](https://github.com/iovisor/bcc/issues/4404), and once it is completed, you will be able to compile BCC-style eBPF kernel code in this way). After writing the eBPF program, running `make` will invoke clang and llvm-strip in the `Makefile` to build the BPF program and remove debug information:

```shell
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../../third_party/vmlinux/x86/ -idirafter /usr/local/include -idirafter /usr/include -c bootstrap.bpf.c -o bootstrap.bpf.o
llvm-strip -g bootstrap.bpf.o # strip useless DWARF info
```

Then we provide a specialized bpftool for Wasm, which generates C header files from BPF programs:

```shell
../../third_party/bpftool/src/bpftool gen skeleton -j bootstrap.bpf.o > bootstrap.skel.h
```

Since the C memory layout for eBPF itself is the same as the instruction set of the current machine, but Wasm has a specific memory layout (e.g., the current machine is 64-bit, and the Wasm virtual machine is 32-bit, so the C struct layout, pointer width, endianness, etc. may be different), in order to ensure that eBPF programs can communicate correctly with Wasm, we need to customize a specialized bpftool and other tools to generate a user space development framework that can work in Wasm.

The skeleton contains a skeleton for a BPF program, used to manipulate BPF objects and control the lifecycle of the BPF program, for example:

```c
    struct bootstrap_bpf {
        struct bpf_object_skeleton *skeleton;
        struct bpf_object *obj;
        struct {
            struct bpf_map *exec_start;
            struct bpf_map *rb;
            struct bpf_map *rodata;
        } maps;
        struct {
            struct bpf_program *handle_exec;
            struct bpf_program *handle_exit;
        } progs;
        struct bootstrap_bpf__rodata {
            unsigned long long min_duration_ns;
        } *rodata;
        struct bootstrap_bpf__bss {
            uint64_t /* pointer */ name_ptr;
        } *bss;
    };
```

We will convert all pointers to integers based on the pointer size of the eBPF program's target instruction set, for example, `name_ptr`. In addition, padding bytes will be explicitly added to the structure to ensure that the structure layout matches the target, for example using `char __pad0[4];`. We will also use `static_assert` to ensure that the size of the structure matches the type length in the original BTF (BPF Type Format) information.### Building User-Space Wasm Code and Accessing Kernel-Space Data

We assume the use of wasi-sdk to build the wasm binary from C/C++ code. You can also use the emcc toolchain to build the wasm binary, and the commands should be similar. You can run the following command to install wasi-sdk:

```sh
wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-17/wasi-sdk-17.0-linux.tar.gz
tar -zxf wasi-sdk-17.0-linux.tar.gz
sudo mkdir -p /opt/wasi-sdk/ && sudo mv wasi-sdk-17.0/* /opt/wasi-sdk/
```

Then running `make` will compile the C code to generate the Wasm bytecode in the `Makefile` using wasi-clang:

```sh
/opt/wasi-sdk/bin/clang -O2 --sysroot=/opt/wasi-sdk/share/wasi-sysroot -Wl,--allow-undefined -o bootstrap.wasm bootstrap.c
```

Since the C structure layout on the host (or eBPF side) might be different from the target (Wasm side), you can use ecc and our wasm-bpftool to generate the C header file for the user-space code:

```sh
ecc bootstrap.h --header-only
../../third_party/bpftool/src/bpftool btf dump file bootstrap.bpf.o format c -j > bootstrap.wasm.h
```

For example, the original kernel-side header file contains the following structure definition:

```c
struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char exit_event;
};
```

Our tool will transform it to:

```c
struct event {
    int pid;
    int ppid;
    unsigned int exit_code;
    char __pad0[4];
    unsigned long long duration_ns;
    char comm[16];
    char filename[127];
    char exit_event;
} __attribute__((packed));
static_assert(sizeof(struct event) == 168, "Size of event is not 168");
```

**Note: This process and tool are not always necessary. For simple applications, you can do it manually.** For cases where both kernel-side and Wasm applications use C/C++ languages, you can manually write all event structure definitions, use `__attribute__((packed))` to avoid padding bytes, and convert all pointers between the host and Wasm side to the correct integers. All types must have the same size and layout as the host on the Wasm side.

For complex programs, manually confirming the correct memory layout is difficult. Therefore, we have created a Wasm-specific `bpftool` that generates a C header file containing all type definitions and the correct structure layout from `BTF` information for user-space code. By using a similar approach, you can convert all structure definitions in the eBPF program to the memory layout on the Wasm side at once, ensuring endianness consistency to access correctly.

For cases where Wasm is not developed using the C language, with the help of Wasm's component model, we can also output these BTF information structure definitions as wit type declarations, and then use the wit-bindgen tool in user-space code to generate type definitions for multiple languages (such as C/C++/Rust/Go) at once. This will be described in detail in the section on how to write eBPF programs in Rust in Wasm, and we will continue to improve these steps and toolchains to enhance the programming experience of Wasm-bpf programs.

We provide a libbpf API library for Wasm programs that includes only header files. You can find it in libbpf-wasm.h (wasm-include/libbpf-wasm.h), which contains some commonly used user-space libbpf APIs and type definitions. Wasm programs can use the libbpf API to manipulate BPF objects, for example:

```c"./* Load and verify BPF application */
skel = bootstrap_bpf__open();
/* Parameterize BPF code with minimum duration parameter */
skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
/* Load & verify BPF programs */
err = bootstrap_bpf__load(skel);
/* Attach tracepoints */
err = bootstrap_bpf__attach(skel);

The rodata section is used to store constants in the BPF program, and these values will be mapped to the correct offsets in the object file generated by bpftool gen skeleton. After opening, the values can be modified through memory mapping, so there is no need to compile the libelf library in Wasm. The BPF object can still be dynamically loaded and manipulated at runtime.

The C code on the Wasm side is slightly different from the local libbpf code, but it can provide most of the functionalities from the eBPF side. For example, polling from a ring buffer or perf buffer, accessing maps from both the Wasm and eBPF sides, loading, attaching, and detaching BPF programs, etc. It can support a wide range of eBPF program types and maps, covering most use cases of eBPF programs in domains such as tracing, networking, and security.

Due to the lack of certain functionalities on the Wasm side, such as signal handler support (as of February 2023), the original C code may not be directly compilable to wasm. You may need to make slight modifications to the code to make it work. We will make best efforts to make the libbpf API on the wasm side as similar as possible to the libbpf API typically used in user space so that user space code can be directly compiled to wasm in the future. We will also provide more language bindings (e.g., Go) for wasm-based eBPF program development libraries as soon as possible.

You can use the polling API in user space programs to retrieve data uploaded from kernel space. It is a wrapper for the ring buffer and perf buffer, allowing user space code to use the same API to poll events from either a ring buffer or a perf buffer, depending on the type specified in the BPF program. For example, ring buffer polling is defined as `BPF_MAP_TYPE_RINGBUF`:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
```

You can use the following code in user space to poll events from the ring buffer:

```c
rb = bpf_buffer__open(skel->maps.rb, handle_event, NULL);
/* Process events */
printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID",
       "PPID", "FILENAME/EXIT CODE");
while (!exiting) {
    // poll buffer
    err = bpf_buffer__poll(rb, 100 /* timeout, ms */);
```

Ring buffer polling does not require serialization overhead. The bpf_buffer__poll API will call the handle_event callback function to process event data from the ring buffer:

```c

static int
handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    ...
    if (e->exit_event) {
        printf("%-8s %-5s %-16s %-7d %-7d [%u]", ts, "EXIT", e->comm, e->pid,
               e->ppid, e->exit_code);
        if (e->duration_ns)
            printf(" (%llums)", e->duration_ns / 1000000);
        printf("\n");
    }
    ...
    return 0;
}
```The Markdown content has been translated to English while preserving the original formatting:

"Runtime is based on the libbpf CO-RE (Compile Once, Run Everywhere) API, which is used to load BPF objects into the kernel. Therefore, wasm-bpf programs are not affected by the kernel version they are compiled with and can run on any kernel version that supports BPF CO-RE.

### Accessing and updating map data of eBPF programs from user-space programs

runqlat is a more complex example that shows the scheduler run queue latency through a histogram, displaying how long a task has waited to run.

```console
$ sudo ./wasm-bpf runqlat.wasm -h
Summarize run queue (scheduler) latency as a histogram.

USAGE: runqlat [--help] [interval] [count]

EXAMPLES:
    runqlat         # summarize run queue latency as a histogram
    runqlat 1 10    # print 1 second summaries, 10 times
$ sudo ./wasm-bpf runqlat.wasm 1

Tracing run queue latency... Hit Ctrl-C to end.

     usecs               : count    distribution
         0 -> 1          : 72       |*****************************           |
         2 -> 3          : 93       |*************************************   |
         4 -> 7          : 98       |****************************************|
         8 -> 15         : 96       |*************************************** |
        16 -> 31         : 38       |***************                         |
        32 -> 63         : 4        |*                                       |
        64 -> 127        : 5        |**                                      |
       128 -> 255        : 6        |**                                      |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 1        |                                        |
```

In runqlat, the `map` API is used to access and directly read data from a `map` in the kernel from user-space, for example:

```c
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_lookup_elem(fd, &next_key, &hist);
        ...
        lookup_key = next_key;
    }
    lookup_key = -2;
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_delete_elem(fd, &next_key);
        ...
        lookup_key = next_key;
    }
```".Instructions: Translate the following Chinese text to English 
while maintaining the original formatting: "When running wasm code, shared memory will be used to access the kernel map. The kernel space can directly copy data to the stack of the Wasm virtual machine in user space, without the additional copy overhead between the user space host program and the Wasm runtime. Similarly, for type definitions shared between the Wasm virtual machine and the kernel space, careful checking is required to ensure that they have consistent types in both Wasm and kernel space.

The `bpf_map_update_elem` function can be used to update the eBPF map in user space programs to update the kernel's eBPF map, for example:

```c
        cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
        cgfd = open(env.cgroupspath, O_RDONLY);
        if (cgfd < 0) {
            ...
        }
        if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
            ...
        }
```

Therefore, the eBPF program in the kernel can obtain configurations from the Wasm program side, or receive messages during runtime.

### More examples: socket filter and LSM

In the repository, we also provide more examples, such as using socket filters to monitor and filter packets:

```c
SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
    struct so_event *e;
    __u8 verlen;
    __u16 proto;
    __u32 nhoff = ETH_HLEN;

    bpf_skb_load_bytes(skb, 12, &proto, 2);
    ...

    bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
    bpf_skb_load_bytes(skb, nhoff + ((verlen & 0xF) << 2), &(e->ports), 4);
    e->pkt_type = skb->pkt_type;
    e->ifindex = skb->ifindex;
    bpf_ringbuf_submit(e, 0);

    return skb->len;
}
```

Linux Security Modules (LSM) is a hook-based framework for implementing security policies and mandatory access control in the Linux kernel. Until now, there have been two choices for enforcing security policy goals: configuring existing LSM modules (such as AppArmor and SELinux) or writing custom kernel modules.

Linux Kernel 5.7 introduces a third option: LSM eBPF. LSM BPF allows developers to write custom policies without configuring or loading kernel modules. LSM BPF programs are verified at load time and then executed when reaching the LSM hook in the call path. For example, we can use LSM in a Wasm lightweight container to restrict file system operations:

```c
// all lsm the hook point refer https://www.kernel.org/doc/html/v5.2/security/LSM.html
SEC("lsm/path_rmdir")
int path_rmdir(const struct path *dir, struct dentry *dentry) {
  char comm[16];
  bpf_get_current_comm(comm, sizeof(comm));
  unsigned char dir_name[] = "can_not_rm";
  unsigned char d_iname[32];
  bpf_probe_read_kernel(&d_iname[0], sizeof(d_iname),
                        &(dir->dentry->d_iname[0]));

  bpf_printk("comm %s try to rmdir %s", comm, d_iname);
  for (int i = 0;i<sizeof(dir_name);i++){
    if (d_iname[i]!=dir_name[i]){
        return 0;
    }
  }
  return -1;
}
```

## Summary

In this example, we discuss how to use C/C++ language to write eBPF programs and compile them into Wasm modules. For more complete code, please refer to our GitHub repository: <https://github.com/eunomia-bpf/wasm-bpf>.

In the next article, we will discuss how to write eBPF programs using Rust and compile them into Wasm modules. We will also cover using OCI images to publish, deploy, and manage eBPF programs, similar to the experience with Docker.

Next, we will continue to improve the experience of developing and running eBPF programs in multiple languages within Wasm. We will provide more comprehensive examples, user-level development libraries/toolchains, and more specific use cases.

## Reference

- wasm-bpf GitHub repository: <https://github.com/eunomia-bpf/wasm-bpf>
- What is eBPF: <https://ebpf.io/what-is-ebpf>
- WASI-eBPF: <https://github.com/WebAssembly/WASI/issues/513>
- Anolis Community eBPF Technology Exploration SIG: <https://openanolis.cn/sig/ebpfresearch>
- eunomia-bpf project: <https://github.com/eunomia-bpf/eunomia-bpf>
- eunomia-bpf project Anolis Gitee mirror: <https://gitee.com/anolis/eunomia>
- Wasm-bpf: Bridging the gap between WebAssembly and eBPF kernel programming: <https://mp.weixin.qq.com/s/2InV7z1wcWic5ifmAXSiew>
- When WASM meets eBPF: Writing, distributing, loading, and running eBPF programs using WebAssembly: <https://zhuanlan.zhihu.com/p/573941739>
- Teaching you how to use eBPF LSM to hotfix Linux kernel vulnerabilities: <https://www.bilibili.com/read/cv19597563>
