# TODO list

## 1. wasm + ebpf serverless runtime

No Provisioned Concurrency: Fast RDMA-codesigned Remote Fork for Serverless Computing

无服务器平台基本上面临着容器启动时间和配置并发性（即缓存实例）之间的权衡，而频繁的远程容器初始化需求则进一步夸大了这一点。本文介绍了MITOSIS，一个提供快速远程分叉的操作系统基元，它利用了操作系统内核与RDMA的深度代码设计。通过利用RDMA的快速远程读取能力和跨无服务器容器的部分状态转移，MITOSIS缩小了本地和远程容器初始化之间的性能差距。MITOSIS是第一个在一秒钟内从一个实例中分叉出超过10,000个新的容器，跨越多台机器，同时允许新容器有效地转移被分叉的容器的预物质化状态。我们在Linux上实现了MITOSIS，并将其与流行的无服务器平台FN集成。在真实世界的无服务器工作负载的负载高峰下，MITOSIS将函数的尾部延迟降低了89%，内存使用量也降低了几个数量级。对于需要状态转移的无服务器工作流，MITOSIS将其执行时间提高了86%。

文章：

- <https://octo.vmware.com/mitosis-an-efficient-way-to-boost-application-performance-on-large-machines/>
- <https://arxiv.org/abs/2203.10225>

MITOSYS 的 ebpf 重构：

- Github 内核模块：<https://github.com/ProjectMitosisOS/mitosis-core>

We decouple the fork into two phases (see Figure 7): The
user can first call fork_prepare to generate the parent’s
metadata (called descriptor) related to remote fork.

The descriptor is globally identified by the local unique handle_-
id and key (generated and returned by the prepared call)
and the parent machine’s RDMA address. Given the identifier,
users can start a child via fork_resume at another machine

Works:

- The major MITOSIS remote fork system calls（有自己的系统调用）
- We retrofit DCT [1], an underutilized but widely supported
advanced RDMA feature with fast and scalable connection
setups to carry out communications between kernels
- We propose a registration-free memory control method
(§5.4) that transforms RNIC’s memory checks to connection
permission checks. We further make the checks efficient by
utilizing DCT’s scalable connection setup feature.
- To this end, we onload the lifecycle management to the
serverless platform (§6.3). The observation is that serverless
coordinators (nodes that invoke functions via fork) naturally
maintain the runtime information of the forked containers.

个人理解：

- 如何获取一个正确的运行时进程的所有状态信息（这个应该好办，可能也有对应的方案）
- 如何在对面的机器上完全恢复现场（可能需要一点内核模块协助）

We choose to implement MITOSIS in the kernel for performance
considerations. First, a user-space solution cannot directly
access the physical memory of the container, so it pays
the checkpointing overhead (see §3). Moreover, the kernel
can establish RDMA connections more efficiently (see KRCore [11]), and the kernel-space page fault handler is much
faster than the user-space fault handler

很大程度上，把更多的设备放在内核里面是性能考虑，所以问题回到了如何分配 eBPF 程序在用户空间和内核空间的部分；

### 其他一些可能相关的工作

SPRIGHT: Extracting the Server from Serverless Computing! High performance eBPF-based Event-driven, Shared-memory Processing

    <https://dl.acm.org/doi/10.1145/3544216.3544259>

    Serverless computing promises an efficient, low-cost compute capability in cloud environments. However, existing solutions, epitomized by open-source platforms such as Knative, include heavyweight components that undermine this goal of serverless computing. Additionally, such serverless platforms lack dataplane optimizations to achieve efficient, high-performance function chains that facilitate the popular microservices development paradigm. Their use of unnecessarily complex and duplicate capabilities for building function chains severely degrades performance. 'Cold-start' latency is another deterrent.

    We describe SPRIGHT, a lightweight, high-performance, responsive serverless framework. SPRIGHT exploits shared memory processing and dramatically improves the scalability of the dataplane by avoiding unnecessary protocol processing and serialization-deserialization overheads. SPRIGHT extensively leverages event-driven processing with the extended Berkeley Packet Filter (eBPF). We creatively use eBPF's socket message mechanism to support shared memory processing, with overheads being strictly load-proportional. Compared to constantly-running, polling-based DPDK, SPRIGHT achieves the same dataplane performance with 10× less CPU usage under realistic workloads. Additionally, eBPF benefits SPRIGHT, by replacing heavyweight serverless components, allowing us to keep functions 'warm' with negligible penalty.

    Our preliminary experimental results show that SPRIGHT achieves an order of magnitude improvement in throughput and latency compared to Knative, while substantially reducing CPU usage, and obviates the need for 'cold-start'.

    SPRIGHT利用共享内存处理，并且戏剧性的通过避免没必要的协议处理和序列化/反序列化开销，提升了数据面的扩展性。SPRIGHT广泛地使用eBPF进行事件驱动的处理。作者创造性的使用eBPF的socket消息机制来支持共享内存处理，其开销严格的与负载成比例。在真实的负载下，与不间断的运行、基于轮询的DPDK相比，SPRIGHT能够在使用10倍少的CPU使用量的情况下，实现相同的数据面性能。除此之外，eBPF通过代替重量级的无服务组件让SPRIGHT变好，让作者能够在开销可以忽略的情况下，保持函数“暖”（warm）。作者的初步实验结果表明，与Knative相比，SPRIGHT在吞吐和时延上有一个数量级的提升，同时实质上减少了CPU的用量，并且避免了“冷启动”的需求。

    SIGCOMM '22: Proceedings of the ACM SIGCOMM 2022 Conference

    It intercepts incoming requests to the function chain and copies the payload into a shared memory region. This enables zero-copy processing within the chain, avoids unnecessary serialization/deserialization and protocol stack processing. The SPRIGHT gateway invokes the function chain for requests, processes the results, and constructs the HTTP response to external clients. SPRIGHT assumes that functions in the same chain run within the same node, to derive the benefits of sharing the memory between functions.

    To accelerate the data path outside the function chain, we utilize
    XDP/TC hooks [67] in eBPF to forward packets between other
    serverless dataplane components, e.g., ingress gateway and to/from
    the chain. An XDP/TC hook processes packets at the early stage of
    the kernel receive (RX) path before packets enter into the kernel
    iptables [36, 45], resulting in substantial dataplane performance
    improvement without dedicated resource consumption, compared
    to a constantly running queue proxy that depends on the kernel
    protocol stack

    感觉思路挺类似的：RDMA vs XDP/TC，然后构造和恢复对应的状态，并且加速数据传输

- Sledge: A serverless-first, light-weight wasm runtime for the edge

    <https://dl.acm.org/doi/abs/10.1145/3423211.3425680>

- Faasm: Lightweight Isolation for Efficient Stateful Serverless Computing

    Serverless computing is an excellent fit for big data processing because it can scale quickly and cheaply to thousands of parallel functions. Existing serverless platforms isolate functions in ephemeral, stateless containers, preventing them from directly sharing memory. This forces users to duplicate and serialise data repeatedly, adding unnecessary performance and resource costs. We believe that a new lightweight isolation approach is needed, which supports sharing memory directly between functions and reduces resource overheads.

    We introduce Faaslets, a new isolation abstraction for high-performance serverless computing. Faaslets isolate the memory of executed functions using \emph{software-fault isolation} (SFI), as provided by WebAssembly, while allowing memory regions to be shared between functions in the same address space. Faaslets can thus avoid expensive data movement when functions are co-located on the same machine. Our runtime for Faaslets, Faasm, isolates other resources, e.g. CPU and network, using standard Linux cgroups, and provides a low-level POSIX host interface for networking, file system access and dynamic loading. To reduce initialisation times, Faasm restores Faaslets from already-initialised snapshots. We compare Faasm to a standard container-based platform and show that, when training a machine learning model, it achieves a 2× speed-up with 10× less memory; for serving machine learning inference, Faasm doubles the throughput and reduces tail latency by 90%.

    <https://arxiv.org/abs/2002.09344>

    Shillaker S, Pietzuch P. Faasm: Lightweight isolation for efficient stateful serverless computing[C]//2020 {USENIX} Annual Technical Conference ({USENIX}{ATC} 20). 2020: 419-433.

## 2. TVM / Taichi / OPAE：让 eBPF 和 WASI/Wasm 结合起来，打通用户态和内核态的可编程机制，实现更为通用的并行计算模型（可能更偏向于编译后端层面）

Taichi：High-performance parallel programming in Python

- <https://www.taichi-lang.org/>
- <https://github.com/taichi-dev/taichi>
- <https://docs.taichi-lang.org/docs/compilation>
- Taichi + MPI: <https://zhuanlan.zhihu.com/p/581896682>
- <https://github.com/AmesingFlank/taichi.js> taichi 后端生成的代码编译为 Wasm，然后在浏览器里面运行
- 尝试把 Taichi 的 wasm 后端放在 WAMR 这样的服务器端的 wasm runtime 里面调度和并行加速；

TVM: An Automated End-to-End Optimizing Compiler for Deep Learning

- （本质上很多的工作可能都是会在编译器的层面进行的）
- <https://tvm.apache.org/2020/05/14/compiling-machine-learning-to-webassembly-and-webgpu>，还是用 JS 的胶水代码，能否迁移到使用 WASI/Wasm，在服务器端调度和运行？
- <https://tvm.apache.org/2018/03/12/webgl>
- <https://github.com/WebAssembly/wasi-nn>
- 更进一步，有没有可能把生成的神经网络塞进 eBPF 里面运行？

### 需要结合编译器做更进一步的探索

### eunomia-bpf 轻量级 eBPF + Wasm 编译、运行时开源项目：希望在编译方面有更多的探索

通用、轻量级多语言下一代 ebpf 开发框架/组件库:

1. 内核态前端支持多种语言语法: bcc/bpftrace/libbpf，或者直接提供对象文件也可以，生成通用的中间产物（配置文件 meta data，JSON 或者 yaml + libbpf 支持的 co-re 的 elf 文件），让 bcc 重新支持 aot 和 co-re
2. aot 或者 jit 都可以，编译工具链和运行时完全分离，保证不同版本编译工具链和运行时之间的兼容性
3. 用户态也支持多种语言（提供 c api，和各种各样的基于 c 的 ffi 绑定，编译成 native 的代码，或者在 wasm 里面开发运行用户态程序），也可以完全不需要用户态开发语言，只在内核态进行；

我们希望 eunomia-bpf 成为一个以类库或者松散组合的框架的方式提供，让其他公司和个人，想要基于自己的内核态 ebpf 基础设施，搭建一个类似的用户态开发运行环境，或者完整的开发平台、插件运行时，变得更容易很多。希望在编译方面做更多的探索。

### 可能的方向

- 多种语言混合，多种编程模型混合，简化 Wasm + eBPF 的编译和使用方式；
- 自动调度和并行化轻量级 eBPF 函数和 Wasm 轻量级容器；
- 和 MLIR 之类的一些新技术相结合，进行更进一步的编译优化和场景拓展；

## 3. ZKP 移植工作 & 其他一些证明可行的移植工作（可能更多偏向于软件工程化）

<https://github.com/hyperledger-labs/private-data-objects/blob/main/common/interpreter/wawaka_wasm/README.md>
