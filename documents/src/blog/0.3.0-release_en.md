# eunomia-bpf 0.3.0 Release: Easily Build, Package, and Publish Full eBPF Applications by Writing Kernel-Mode Code

## Introduction to eunomia-bpf

eBPF, derived from BPF, is an efficient and flexible virtual machine component within the kernel. It executes bytecode at various kernel hook points in a secure manner, enabling developers to build performance analysis tools, software-defined networks, security solutions, and more. However, there are some inconveniences when it comes to developing and using eBPF applications:

- Setting up and developing eBPF programs is a complex task. It requires handling interactions and information processing between kernel mode and user mode, as well as configuring the environment and writing corresponding build scripts.
- Currently, it is difficult to achieve compatibility and unified management among tools written in different user mode languages like C, Go, Rust, etc. There is a challenge in integrating various development ecosystems, such as supporting multiple architectures, languages, and kernel versions. How can we package, distribute, and publish binary eBPF programs in a standardized and convenient way? Additionally, there is a need to easily adjust mounting points, parameters, and other aspects of eBPF programs.
- How can we make it easier to use eBPF tools? Is it possible to download and use them with just one command from the cloud, similar to Docker? Can we run eBPF programs as services, allowing hot updates and dynamic insertion/removal through HTTP requests and URLs?

[eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) is an open-source eBPF dynamic loading runtime and development toolchain designed to simplify the development, building, distribution, and execution of eBPF programs. It is based on the CO-RE lightweight development framework of libbpf.

With eunomia-bpf, you can:

- Write only kernel-mode code when developing eBPF programs or tools, and automatically obtain kernel-mode export information.
- Use Wasm for developing user-mode interactive programs. The Wasm virtual machine controls the loading, execution, and data processing of the entire eBPF program.
- eunomia-bpf can package pre-compiled eBPF programs into universal JSON or Wasm modules, enabling distribution across architectures and kernel versions without the need for recompilation, and facilitating dynamic loading and execution.

eunomia-bpf consists of a compilation toolchain and a runtime library. Compared to traditional frameworks like BCC and native libbpf, eunomia-bpf greatly simplifies the development process of eBPF programs. In most cases, you only need to write kernel-mode code to easily build, package, and publish complete eBPF applications. The kernel-mode eBPF code ensures 100% compatibility with mainstream development frameworks like libbpf, libbpfgo, libbpf-rs, etc. When you need to write user-mode code, you can use WebAssembly (Wasm) to develop it in multiple languages. Compared to script tools like bpftrace, eunomia-bpf offers similar convenience and is not limited to tracing. It can be used in various scenarios like networking, security, and more.

> - eunomia-bpf project on Github: <https://github.com/eunomia-bpf/eunomia-bpf>
> - gitee mirror: <https://gitee.com/anolis/eunomia>

We have released the latest version 0.3, which optimizes the overall development and usage process. It also supports more types of eBPF programs and maps.

## Runtime Optimization: Enhanced Functionality, Multiple Program Types

1. By writing only kernel-mode code, you can obtain corresponding output information and print it in a readable and well-organized manner to the standard output. Let's take the example of a simple eBPF program, opensnoop, which traces all open system calls:

    Header file opensnoop.h

    ```c
    #ifndef __OPENSNOOP_H
    #define __OPENSNOOP_H

    #define TASK_COMM_LEN 16
    #define NAME_MAX 255
    #define INVALID_UID ((uid_t)-1)

    // used for export event
    struct event {
      /* user terminology for pid: */
      unsigned long long ts;
      int pid;
      int uid;
      int ret;
      int flags;
      char comm[TASK_COMM_LEN];
      char fname[NAME_MAX];
    };

    #endif /* __OPENSNOOP_H */
    ```

    Kernel-mode code opensnoop.bpf.c

    ```c
    #include <vmlinux.h>".
format: Return only the translated content, not including the original text.```c
#include <bpf/bpf_helpers.h>
#include "opensnoop.h"

struct args_t {
  const char *fname;
  int flags;
};

/// Process ID to trace
const volatile int pid_target = 0;
/// Thread ID to trace
const volatile int tgid_target = 0;
/// @description User ID to trace
const volatile int uid_target = 0;
/// @cmdarg {"default": false, "short": "f", "long": "failed"}
const volatile bool targ_failed = false;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);
  __type(value, struct args_t);
} start SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool valid_uid(uid_t uid) {
  return uid != INVALID_UID;
}

static __always_inline
bool trace_allowed(u32 tgid, u32 pid)
{
  u32 uid;

  /* filters */
  if (tgid_target && tgid_target != tgid)
    return false;
  if (pid_target && pid_target != pid)
    return false;
  if (valid_uid(uid_target)) {
    uid = (u32)bpf_get_current_uid_gid();
    if (uid_target != uid) {
      return false;
    }
  }
  return true;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
  u64 id = bpf_get_current_pid_tgid();
  /* use kernel terminology here for tgid/pid: */
  u32 tgid = id >> 32;
  u32 pid = id;

  /* store arg info for later lookup */
  if (trace_allowed(tgid, pid)) {
    struct args_t args = {};
    args.fname = (const char *)ctx->args[0];
    args.flags = (int)ctx->args[1];
    bpf_map_update_elem(&start, &pid, &args, 0);
  }
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
``````c
u64 id = bpf_get_current_pid_tgid();
/* use kernel terminology here for tgid/pid: */
u32 tgid = id >> 32;
u32 pid = id;

/* store arg info for later lookup */
if (trace_allowed(tgid, pid)) {
  struct args_t args = {};
  args.fname = (const char *)ctx->args[1];
  args.flags = (int)ctx->args[2];
  bpf_map_update_elem(&start, &pid, &args, 0);
}
return 0;
}

static __always_inline
int trace_exit(struct trace_event_raw_sys_exit* ctx)
{
  struct event event = {};
  struct args_t *ap;
  int ret;
  u32 pid = bpf_get_current_pid_tgid();

  ap = bpf_map_lookup_elem(&start, &pid);
  if (!ap)
    return 0; /* missed entry */
  ret = ctx->ret;
  if (targ_failed && ret >= 0)
    goto cleanup; /* want failed only */

  /* event data */
  event.pid = bpf_get_current_pid_tgid() >> 32;
  event.uid = bpf_get_current_uid_gid();
  bpf_get_current_comm(&event.comm, sizeof(event.comm));
  bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ap->fname);
  event.flags = ap->flags;
  event.ret = ret;

  /* emit event */
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
            &event, sizeof(event));

cleanup:
  bpf_map_delete_elem(&start, &pid);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
{
  return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
  return trace_exit(ctx);
}

/// Trace open family syscalls.
char LICENSE[] SEC("license") = "GPL";
```

Compile and run:

```console
$ ecc opensnoop.bpf.c opensnoop.h
Compiling bpf object...
Generating export types...
Packing ebpf object and config into package.json...
$ sudo ecli examples/bpftools/opensnoop/package.json".
```

Compilation and execution:**Markdown Translation:**

```
TIME     TS    PID   UID   RET   FLAGS   COMM        FNAME
20:31:50  0    1     0     51    524288  systemd     /proc/614/cgroup
20:31:50  0    33182 0     25    524288  ecli        /etc/localtime
20:31:53  0    754   0     6     0       irqbalance  /proc/interrupts
20:31:53  0    754   0     6     0       irqbalance  /proc/stat
20:32:03  0    754   0     6     0       irqbalance  /proc/interrupts
20:32:03  0    754   0     6     0       irqbalance  /proc/stat
20:32:03  0    632   0     7     524288  vmtoolsd    /etc/mtab
20:32:03  0    632   0     9     0       vmtoolsd    /proc/devices

$ sudo ecli examples/bpftools/opensnoop/package.json --pid_target 754
TIME     TS    PID   UID   RET   FLAGS  COMM        FNAME
20:34:13  0    754   0     6     0      irqbalance  /proc/interrupts
20:34:13  0    754   0     6     0      irqbalance  /proc/stat
20:34:23  0    754   0     6     0      irqbalance  /proc/interrupts
20:34:23  0    754   0     6     0      irqbalance  /proc/stat
```

Or compile using Docker:

```shell
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```

After compiling and publishing, you can easily start any eBPF program from the cloud with a single command, for example:

```bash
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli     # download the release from https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecli
sudo ./ecli https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/package.json # simply run a pre-compiled ebpf code from a url
sudo ./ecli sigsnoop:latest # run with a name and download the latest version bpf tool from our repo
```

The complete code is available here: [https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/opensnoop](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/opensnoop)

2. Support the automatic generation of user command-line parameters based on comments in the code.

For example, to implement a PID filter in an eBPF program, you only need to write kernel code and declare a global variable in eBPF to automatically generate command-line parameters:

```c
/// Process ID to trace
const volatile pid_t pid_target = 0;
/// Thread ID to trace".
``````
const volatile pid_t tgid_target = 0;
/// @description User ID to trace
const volatile uid_t uid_target = 0;
/// @cmdarg {"default": false, "short": "f", "long": "failed"}
/// @description target pid to trace
const volatile bool targ_failed = false;
```

We will extract the description information of the comments and put it in the configuration file, and convert it into command line arguments for the eBPF application. Take tracing all open system calls with opensnoop as an example:

```console
$ sudo ecli  examples/bpftools/opensnoop/package.json -h
Usage: opensnoop_bpf [--help] [--version] [--verbose] [--pid_target VAR] [--tgid_target VAR] [--uid_target VAR] [--failed]

Trace open family syscalls.

Optional arguments:
  -h, --help    shows help message and exits
  -v, --version prints version information and exits
  --verbose     prints libbpf debug information
  --pid_target  Process ID to trace
  --tgid_target Thread ID to trace

$ sudo ecli examples/bpftools/opensnoop/package.json --pid_target 754
TIME     TS      PID     UID     RET     FLAGS   COMM    FNAME
20:34:13  0      754     0       6       0       irqbalance /proc/interrupts
20:34:13  0      754     0       6       0       irqbalance /proc/stat
20:34:23  0      754     0       6       0       irqbalance /proc/interrupts
20:34:23  0      754     0       6       0       irqbalance /proc/stat
```

3. Support automatically collecting and synthesizing maps that are not ring buffer or perf event, such as hash map, and print out information or generate histograms.

Previously, the use of ring buffer and perf event was slightly limited, so there needs to be a way to automatically collect data from maps by adding comments in the source code:

```c
/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct hist);
} hists SEC(".maps");
```

It will collect the contents of counters every second (print_map), using runqlat as an example:

```console
$ sudo ecli examples/bpftools/runqlat/package.json -h
Usage: runqlat_bpf [--help] [--version] [--verbose] [--filter_cg] [--targ_per_process] [--targ_per_thread] [--targ_per_pidns] [--targ_ms] [--targ_tgid VAR]
```Summarize run queue (scheduler) latency as a histogram.

    Optional arguments:
      -h, --help            shows help message and exits
      -v, --version         prints version information and exits
      --verbose             prints libbpf debug information
      --filter_cg           set value of bool variable filter_cg
      --targ_per_process    set value of bool variable targ_per_process
      --targ_per_thread     set value of bool variable targ_per_thread
      --targ_per_pidns      set value of bool variable targ_per_pidns
      --targ_ms             set value of bool variable targ_ms
      --targ_tgid           set value of pid_t variable targ_tgid

    Built with eunomia-bpf framework.
    See https://github.com/eunomia-bpf/eunomia-bpf for more information.

    $ sudo ecli examples/bpftools/runqlat/package.json
    key =  4294967295
    comm = rcu_preempt

        (unit)              : count    distribution
            0 -> 1          : 9        |****                                    |
            2 -> 3          : 6        |**                                      |
            4 -> 7          : 12       |*****                                   |
            8 -> 15         : 28       |*************                           |
           16 -> 31         : 40       |*******************                     |
           32 -> 63         : 83       |****************************************|
           64 -> 127        : 57       |***************************             |
          128 -> 255        : 19       |*********                               |
          256 -> 511        : 11       |*****                                   |
          512 -> 1023       : 2        |                                        |
         1024 -> 2047       : 2        |                                        |
         2048 -> 4095       : 0        |                                        |
         4096 -> 8191       : 0        |                                        |
         
         
         
Built with eunomia-bpf framework.
See https://github.com/eunomia-bpf/eunomia-bpf for more information.8192 -> 16383      : 0        |                                        |
        16384 -> 32767      : 1        |                                        |

    $ sudo ecli examples/bpftools/runqlat/package.json --targ_per_process
    key =  3189
    comm = cpptools

        (unit)              : count    distribution
            0 -> 1          : 0        |                                        |
            2 -> 3          : 0        |                                        |
            4 -> 7          : 0        |                                        |
            8 -> 15         : 1        |***                                     |
           16 -> 31         : 2        |*******                                 |
           32 -> 63         : 11       |****************************************|
           64 -> 127        : 8        |*****************************           |
          128 -> 255        : 3        |**********                              |
    ```

    Here is the complete code: <https://github.com/eunomia-bpf/eunomia-bpf/tree/master/examples/bpftools/runqlat>

4. Add support for multiple types of maps like uprobe, tc, etc., allowing additional attach information to be added using annotations, for example:

    ```c

    /// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
    /// @tcopts {"handle":1,  "priority":1}
    SEC("tc")
    int tc_ingress(struct __sk_buff *ctx)
    {
        void *data_end = (void *)(__u64)ctx->data_end;
        void *data = (void *)(__u64)ctx->data;
        struct ethhdr *l2;
        struct iphdr *l3;

        if (ctx->protocol != bpf_htons(ETH_P_IP))
            return TC_ACT_OK;

        l2 = data;
        if ((void *)(l2 + 1) > data_end)
            return TC_ACT_OK;

        l3 = (struct iphdr *)(l2 + 1);
        if ((void *)(l3 + 1) > data_end)
            return TC_ACT_OK;

        bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
        return TC_ACT_OK;
    }
    ```

## Regarding compilation: Improved compilation experience, formatting changes

1. Completely refactored the compilation toolchain and configuration file format, returning to the essence of a configuration file + ebpf bytecode .o format. It no longer requires the packaging to be in JSON format, making it more user-friendly for distribution and human editing of configuration files. It also improves compatibility with libbpf-related toolchains.".2. Support both JSON and YAML formats for configuration files (xxx.skel.yaml and xxx.skel.json), or package them as package.json and package.yaml for distribution;
3. Use BTF information to express symbol types as much as possible, and hide BTF information in binary files to make configuration files more readable and editable, while reusing the BTF handling mechanism provided by libbpf to improve type handling;
4. Support more data export types: enum, struct, bool, etc.
5. Compilation can be done without relying on docker. The binaries and header files can be installed in ~/.eunomia (more friendly to embedded or domestic networks, more convenient to use). The original way of using docker can still be continued;
6. There is no specific restriction on the file name. It does not have to be xxx.bpf.h and xxx.bpf.c. The files to be compiled in the current directory can be specified through ecc;
7. Rename the old xxx.bpf.h header file in the example to xxx.h, to be consistent with libbpf-tools and libbpf-bootstrap, and ensure that the libbpf-related code ecosystem can be reused with 0 code modifications;
8. Greatly optimize compilation speed and reduce compilation dependencies by refactoring the compilation toolchain with Rust, replacing the original Python script.

In the configuration file, you can directly modify progs/attach to control the mounting point, variables/value to control global variables, maps/data to control the data to be placed in the map when loading the ebpf program, and export_types/members to control the data format to be transmitted to the user space, without the need to recompile the eBPF program. The configuration file and bpf.o binary are complementary and should be used together, or packaged as a package.json/yaml for distribution. When packaging, compression will be applied, and generally the combined size of the compressed configuration file and binary is several tens of kilobytes.

Configuration file example:

```yaml
bpf_skel:
  data_sections:
  - name: .rodata
    variables:
    - name: min_duration_ns
      type: unsigned long long
      value: 100
  maps:
  - ident: exec_start
    name: exec_start
    data:
      - key: 123
        value: 456
  - ident: rb
    name: rb
  - ident: rodata
    mmaped: true
    name: client_b.rodata
  obj_name: client_bpf
  progs:
  - attach: tp/sched/sched_process_exec
    link: true
    name: handle_exec
export_types:
- members:
  - name: pid
    type: int
  - name: ppid
    type: int
  - name: comm
    type: char[16]
  - name: filename
    type: char[127]
  - name: exit_event
    type: bool
  name: event
  type_id: 613
```

## Download and install eunomia-bpf

- Install the `ecli` tool for running eBPF programs from the cloud:

    ```console
    $ wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
    $ ./ecli -h
    Usage: ecli [--help] [--version] [--json] [--no-cache] url-and-args
    ....
    ```

- Install the compiler-toolchain for compiling eBPF kernel code to a `config` file or `Wasm` module:

    ```console
    $ wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
    $ ./ecc -h
    eunomia-bpf compiler"Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]
    ....
    ....

```

or use the docker image for compile:

```bash
docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest # compile with docker. `pwd` should contains *.bpf.c files and *.h files.
```

## Development Plans

1. Collaborate with more community partners and gradually establish a standardized eBPF program format that is packaged and distributed using configuration files or Wasm binary. Achieve the goal of compiling once and running everywhere.
2. Work with the LMP community to improve the distribution and runtime standards for eBPF programs based on ORAS, OCI, and Wasm. Enable any eBPF application to be easily pulled from the cloud and run with a single command or seamlessly embedded in other applications, without concerning the architecture and kernel version.
3. Collaborate with the Coolbpf community to enhance remote compilation, support for lower versions, and add support for RPC in the libbpf library.
4. Improve interoperability between user-mode Wasm and eBPF programs, and explore relevant extensions of WASI.

## References

1. [Writing, Distributing, Loading, and Running eBPF Programs using WebAssembly](https://eunomia-bpf.github.io/blog/ebpf-wasm.html)
2. [How to start eBPF journey in the Linux Microscope (LMP) project?](https://eunomia-bpf.github.io/blog/lmp-eunomia.html)
3. [Eunomia-BPF Project Homepage on Longgui Community](https://openanolis.cn/sig/ebpfresearch/doc/640013458629853191)
4. [Eunomia-BPF Project Documentation](https://eunomia-bpf.github.io/)
5. [LMP Project](https://github.com/linuxkerneltravel/lmp)

## Our WeChat Group.