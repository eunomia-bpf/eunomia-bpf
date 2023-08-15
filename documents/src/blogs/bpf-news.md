# eBPF Advanced: Overview of New Kernel Features

The Linux kernel primarily released versions 5.16-5.19, 6.0, and 6.1 in 2022, each of which introduced numerous new features for eBPF. This article will provide a brief introduction to these new features, and for more detailed information, please refer to the corresponding link. Overall, eBPF remains one of the most active modules in the kernel, and its functionality is still rapidly evolving. In a sense, eBPF is rapidly evolving towards a complete kernel-level programmable interface.

<!-- TOC -->

- [eBPF Advanced: Overview of New Kernel Features](#ebpf-advanced-overview-of-new-kernel-features)
  - [BPF kfuncs](#bpf-kfuncs)
  - [Bloom Filter Map: 5.16](#bloom-filter-map-516)
  - [Compile Once – Run Everywhere: Linux 5.17](#compile-once--run-everywherelinux-517)
  - [bpf_loop() Helper Function: 5.17](#bpf_loop-helper-function-517)
  - [BPF_LINK_TYPE_KPROBE_MULTI: 5.18](#bpf_link_type_kprobe_multi-518)
  - [Dynamic Pointers and Type Pointers: 5.19](#dynamic-pointers-and-type-pointers-519)
  - [USDT: 5.19](#usdt-519)
  - [bpf panic: 6.1](#bpf-panic61)
  - [BPF Memory Allocator, Linked List: 6.1](#bpf-memory-allocator-linked-list-61)
  - [User Ring Buffer 6.1](#user-ring-buffer-61)

<!-- /TOC -->

## BPF kfuncs

The BPF subsystem exposes many aspects of kernel internal algorithms and data structures, which naturally leads to concerns about maintaining interface stability when the kernel changes. For a long time, BPF's stance on not providing interface stability guarantees to user space has been somewhat problematic. In the past, kernel developers found themselves having to maintain interfaces that were not intended to be stable. Now the BPF community is starting to consider what it might mean to provide explicit stability guarantees for at least some of its interfaces.

BPF allows programs loaded from user space to be attached to any of a large number of hooks and run in the kernel—after the subsystem's verifier has concluded that those programs won't harm the system. A program gains access to kernel data structures provided by the hook to which it is attached. In some cases, a program can modify those data structures directly, thereby directly affecting the kernel's operation. In other cases, the kernel will take action based on values returned by a BPF program, such as allowing or disallowing a particular operation.

There are also two mechanisms by which the kernel can provide BPF programs with additional functionality. Helper functions have been around since the extended BPF era and are special functions written to be made available to BPF programs. A mechanism called kfuncs is relatively new and allows any kernel function to be made available to BPF, potentially with some restrictions. Kfuncs are simpler and more flexible, and if they were implemented first, it seems unlikely that anyone would have added helpers later. That said, kfuncs have an important limitation in that they can only be accessed by JIT-compiled BPF code, so they are not available on architectures lacking JIT support (which currently includes 32-bit Arm and RISC-V, although patches adding support for these are in development). Each kfunc provides some useful functionality to BPF programs but also exposes some aspects of how the kernel works.

- Reconsidering BPF ABI stability: [Link](https://mp.weixin.qq.com/s/wYDSXuwVgmGw-wmFgBNJcA)
- Documentation/bpf: Add a description of "stable kfuncs" [Link](https://www.spinics.net/lists/kernel/msg4676660.html)

## Bloom Filter Map: 5.16

Bloom filters are space-efficient probabilistic data structures used to quickly test whether an element is a member of a set. In a bloom filter, false positives are possible, but false negatives are not.

This patchset includes benchmarking of bloom filters with configurable numbers of hash values and entries. These benchmarks roughly indicate that, on average, using 3 hash functions is one of the ideal choices. When comparing the bloom filter with 3 hash values used in hashmap lookups to hashmap lookups without bloom filters, the lookup with the bloom filter is approximately 15% faster for 50,000 entries, 25% faster for 100,000 entries, 180% faster for 500,000 entries, and 200% faster for 1 million entries.

- BPF: Implement bloom filter map [Link](https://lwn.net/Articles/868024/)

## Compile Once – Run Everywhere: Linux 5.17".Linux 5.17 added a new feature called Compile Once - Run Everywhere (CO-RE) for eBPF, which greatly simplifies the complexity of handling multi-version kernel compatibility and loop logic in eBPF programs.

The CO-RE project of eBPF relies on the debugging information provided by BPF Type Format (BTF) and goes through the following four steps to enable eBPF programs to adapt to different versions of the kernel:

- First, the bpftool provides a tool to generate header files from BTF, eliminating the need for kernel header files.
- Second, by rewriting the access offsets in the BPF code, the problem of different data structure offsets in different kernel versions is resolved.
- Third, the modifications of data structures in different kernel versions are pre-defined in libbpf to address the issue of incompatible data structures in different kernels.
- Fourth, libbpf provides a series of library functions for detecting kernel features, solving the problem of eBPF programs needing to perform different behaviors in different kernel versions. For example, you can use bpf_core_type_exists() and bpf_core_field_exists() to check if kernel data types and member variables exist, and use the format extern int LINUX_KERNEL_VERSION __kconfig to query kernel configuration options.

With these methods, CO-RE allows eBPF programs to be compiled in the development environment and distributed to machines with different kernel versions, without the need to install various development tools and kernel header files on the target machines. Therefore, the Linux kernel community recommends that all developers use CO-RE and libbpf to build eBPF programs. In fact, if you have looked at the source code of BCC, you will find that BCC has already migrated many tools to CO-RE.

- Detailed explanation of eBPF multi-kernel version compatibility: <https://time.geekbang.org/column/article/534577>
- BPF CO-RE reference guide: <https://nakryiko.com/posts/bpf-core-reference-guide/>

## Helper function bpf_loop(): 5.17

One of the main features of the extended BPF virtual machine is the built-in validator in the kernel, which ensures that all BPF programs can run safely. However, BPF developers often have mixed feelings about the validator; although it can catch many problems before they occur, it is also difficult to satisfy. Comparing it to a well-meaning but rule-constrained and picky bureaucratic organization is not entirely wrong. The bpf_loop() proposal by Joanne Koong is intended to make a type of loop structure more pleasing to the BPF bureaucrats.

In short, that is the purpose of Koong's patch. It adds a new helper function that can be called from BPF code.

```c
    long bpf_loop(u32 iterations, long (*loop_fn)(u32 index, void *ctx),
          void *ctx, u64 flags);
```

A call to bpf_loop() will result in iterative calls to loop_fn(), with the iteration count and the passed ctx as parameters. The flags value is currently unused and must be zero. loop_fn() typically returns 0; returning 1 will immediately end the iteration. No other return values are allowed.

Unlike bpf_for_each_map_elem(), which is limited by BPF map size, the number of iterations for bpf_loop() can be as high as 1<<23 = 8388608 (over 8 million); greatly expanding the range of applications for bpf_loop(). However, bpf_loop() is not limited by the number of BPF instructions (1 million) because the loop occurs inside the bpf_loop() helper function.

- A different approach to BPF loops: <https://lwn.net/Articles/877062/>
- eBPF Talk: Practical experience with loops: <https://mp.weixin.qq.com/s/neOVsMNVWFbwpTSek-_YsA>

## BPF_LINK_TYPE_KPROBE_MULTI: 5.18

This patch set adds a new link type called BPF_TRACE_KPROBE_MULTI, which connects kprobe programs using the fprobe API [1] created by Masami. The fprobe API allows probes to be attached to multiple functions at once and works very fast because it operates on top of ftrace. On the other hand, it restricts the probe points to function entry or return.

- bpf: Add kprobe multi link: <https://lwn.net/Articles/885811/>

## Dynamic Pointers and Type Pointers: 5.19.Instructions: Translate the following Chinese text to English 
while maintaining the original formatting: "All memory accesses in the BPF program use validators for security static checks, and validators perform comprehensive analysis of the program before allowing it to run. While this enables BPF programs to run safely in kernel space, it restricts how the program can use pointers. Until recently, one such restriction was that the size of the memory region referenced by a pointer in a BPF program had to be statically known when loading the BPF program. Joanne Koong recently introduced a patchset that enhances BPF to support loading programs with pointers to dynamically sized memory regions.

Koong's patchset adds support for accessing dynamically sized memory regions in BPF programs, which includes a new feature called dynptrs. The main idea behind dynptrs is to associate pointers to dynamically sized data regions with validators and some metadata used by BPF helper functions, to ensure that access to that region is valid. Koong's patchset creates this association in a newly defined type called struct bpf_dynptr. This structure is opaque to BPF programs.

- <https://mp.weixin.qq.com/s/rz4pd41Y-Cet5YVSAKmCRw>

## USDT: 5.19

Static tracepoints, also known as User-Level Statically Defined Tracing (USDT) probes, are specific locations of interest in an application that a tracer can mount to check code execution and data. They are explicitly defined by developers in the source code and are usually enabled at compile time with flags such as "--enable-trace". The advantage of static tracepoints is that they do not change frequently: developers typically maintain a stable static trace ABI, so tracing tools work across different versions of an application, which is useful, for example, when upgrading a PostgreSQL installation and experiencing performance degradation.

- eBPF Overview Part 5: Tracing User Processes: <https://www.ebpf.top/post/ebpf-overview-part-5/>
- Using user-space tracepoints with BPF: <https://lwn.net/Articles/753601/>

## BPF panic: 6.1

One of the key selling points of the BPF subsystem is that loading BPF programs is safe: the BPF verifier ensures that the program cannot harm the kernel before allowing it to load. As more features are offered to BPF programs, this guarantee may lose some of its strength, but even so, seeing Artem Savkov's proposal to introduce a BPF helper explicitly designed to crash the system may come as a bit of a surprise. If merged in a form resembling the current patchset, it would be a harbinger of a new era in which, at least in certain cases, BPF programs are allowed to deliberately cause havoc.

As Savkov points out, one of the primary use cases for BPF is kernel debugging, and this task is often helped by having a timely crash dump available. By making the panic() function of the kernel available to BPF programs, Savkov attempts to combine these two and allow BPF programs to crash and create crash dumps when certain conditions indicating the problems that developers are looking for are detected. Savkov seems not to be the only one who wants this ability; Jiri Olsa has reported receiving requests for such functionality as well.

- The BPF panic function: <https://lwn.net/Articles/901284/>

## BPF Memory Allocator, Linked List: 6.1

This series introduces BPF objects defined by users in the BTF type of the program. This allows BPF programs to allocate their own objects, build their own object hierarchy, and flexibly construct their own data structures using the basic building blocks provided by the BPF runtime.

Then, we introduce support for singly-owned BPF linked lists. They can be placed in BPF maps or allocated objects and hold these allocated objects as elements. It works as an intrusive set. The aim of doing this is to make the allocated objects part of multiple data structures in the future.

The ultimate goal of this patch and future patches is to allow people to do some limited kernel-style programming in BPF C and allow programmers to flexibly construct their own complex data structures from basic building blocks.

The key difference is that these programs are verified, safe, preserve runtime integrity of the system, and have been proven to have no bugs.

Specific features include:

- Allocating objects
- bpf_obj_new, bpf_obj_drop to allocate and release objects
- Singly-owned BPF linked lists
  - Supporting them in BPF maps
  - Supporting them in allocated objects
- Global spinlocks
- Spinlocks in allocated objects.

Reference: <https://lwn.net/Articles/914833/>

## User Ring Buffer 6.1

This patchset defines a new map type, BPF_MAP_TYPE_USER_RINGBUF, which provides single-user space producer/single-kernel consumer semantics on top of a ring buffer. In addition to the new map type, it adds an auxiliary function called bpf_user_ringbuf_drain() that allows a BPF program to specify a callback with the following signature, to which the samples are published by the helper function.

```c".
format: Return only the translated content, not including the original text.```
void (struct bpf_dynptr *dynptr, void *context).

Then the program can safely read samples from dynptr using the bpf_dynptr_read() or bpf_dynptr_data() helper functions. Currently, there are no available helper functions to determine the size of the samples, but one can easily be added if needed.

libbpf has also added some corresponding APIs:

```c
struct ring_buffer_user *
ring_buffer_user__new(int map_fd,
                      const struct ring_buffer_user_opts *opts);
void ring_buffer_user__free(struct ring_buffer_user *rb);
void *ring_buffer_user__reserve(struct ring_buffer_user *rb,
        uint32_t size);
void *ring_buffer_user__poll(struct ring_buffer_user *rb, uint32_t size,
           int timeout_ms);
void ring_buffer_user__discard(struct ring_buffer_user *rb, void *sample);
void ring_buffer_user__submit(struct ring_buffer_user *rb, void *sample);
```

- bpf: Add user-space-publisher ring buffer map type: <https://lwn.net/Articles/907056/>

> - This article was completed by the eunomia-bpf team and we are exploring the toolchains and runtimes integrating eBPF and WebAssembly: <https://github.com/eunomia-bpf/wasm-bpf>
> - And trying to build some interesting use cases on top of Wasm and eBPF.